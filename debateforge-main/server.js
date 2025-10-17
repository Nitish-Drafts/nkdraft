// server.js
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

mongoose.connect(process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/debateforge', { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// ------------------ Schemas ------------------
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,
  points: { type: Number, default: 0 },
});
const User = mongoose.model('User', userSchema);

/*
Topic schema notes:
- description: now required minimum 50 words (validated server-side on creation)
- opponents: array of { side: 'pro'|'con', email: String } so we can have multiple players per side
- postDebatePoll: counts for poll (pro/con/tie)
- postDebateScores: array of detailed scores from eligible voters
- forumComments: same as comments but used for longer forum conversation
*/
const topicSchema = new mongoose.Schema({
  title: String,
  description: String,
  category: { type: String, default: 'General' },
  creatorStance: String, // 'pro' or 'con'
  creator: String, // email
  opponents: [{ side: String, email: String }], // multiple opponents across sides
  mediator: String, // email
  scheduledFor: Date,
  roomId: String,
  votes: [{ voter: String, scores: Object, eligible: [String] }],
  postDebatePoll: { pro: { type: Number, default: 0 }, con: { type: Number, default: 0 }, tie: { type: Number, default: 0 }, voters: [String] },
  postDebateScores: [{
    scorer: String,
    role: String, // 'viewer' | 'debater' | 'mediator'
    scores: { // each participant scored individually by id/email
      // e.g. { "alice@example.com": { logic: 4, civility: 5 }, "bob@example.com": { logic: 3, civility: 4 } }
    }
  }],
  // forum comments (nested)
  comments: [{ author: String, text: String, parentId: String, timestamp: Date }],
  noShowPenalty: { type: Boolean, default: false },
  endedAt: Date, // when the debate was ended
});
const Topic = mongoose.model('Topic', topicSchema);

// ------------------ Helpers ------------------
function countWords(str) {
  if (!str) return 0;
  return str.trim().split(/\s+/).filter(Boolean).length;
}

async function applyPostDebateScores(topicId) {
  // apply aggregated postDebateScores to user points (averages)
  const topic = await Topic.findById(topicId);
  if (!topic) return;

  // Collect per-user aggregates
  const aggregates = {}; // email -> { logicSum, civilitySum, count }
  for (const record of topic.postDebateScores) {
    const { scorer, role, scores } = record;
    // scores is an object mapping targetEmail -> { logic, civility } (example)
    for (const targetEmail of Object.keys(scores || {})) {
      const sc = scores[targetEmail];
      if (!sc) continue;
      aggregates[targetEmail] = aggregates[targetEmail] || { logicSum: 0, civilitySum: 0, count: 0 };
      aggregates[targetEmail].logicSum += (sc.logic || 0);
      aggregates[targetEmail].civilitySum += (sc.civility || 0);
      aggregates[targetEmail].count += 1;
    }
  }
  // Apply aggregates to user points (you can adjust weightings)
  for (const email of Object.keys(aggregates)) {
    const agg = aggregates[email];
    const avgLogic = agg.logicSum / agg.count;
    const avgCivility = agg.civilitySum / agg.count;
    const addPoints = Math.round((avgLogic * 1.5 + avgCivility * 1.0)); // example weighting
    const user = await User.findOne({ email });
    if (user) {
      user.points = (user.points || 0) + addPoints;
      await user.save();
    }
  }
}

// ------------------ Auth ------------------
app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Missing email or password' });
    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashed });
    await user.save();
    res.json({ user: { email } });
  } catch (err) {
    console.error('Register error:', err);
    res.status(400).json({ error: 'User exists or invalid data' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (user && await bcrypt.compare(password, user.password)) {
      return res.json({ user: { email } });
    }
    return res.status(401).json({ error: 'Invalid credentials' });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// ------------------ Topics ------------------
app.get('/topics', async (req, res) => {
  try {
    const { category } = req.query;
    const q = category ? { category } : {};
    const topics = await Topic.find(q);
    // add convenience field: canEnter now?
    const now = new Date();
    const mapped = topics.map(t => {
      const scheduledFor = t.scheduledFor ? new Date(t.scheduledFor) : null;
      const canEnter = !scheduledFor || now >= scheduledFor;
      return { ...t.toObject(), canEnter };
    });
    res.json(mapped);
  } catch (err) {
    console.error('Get topics error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Create topic — requires description >= 50 words
app.post('/topics', async (req, res) => {
  try {
    const { title, description, category, stance, creator, scheduledFor } = req.body;
    if (!title || !description || !stance || !creator) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    const words = countWords(description || '');
    if (words < 50) {
      return res.status(400).json({ error: 'Description must be at least 50 words' });
    }
    const roomId = Math.random().toString(36).substring(2, 10);
    const topic = new Topic({
      title,
      description,
      category: category || 'General',
      creatorStance: stance,
      creator,
      opponents: [], // empty initially
      mediator: null,
      scheduledFor: scheduledFor ? new Date(scheduledFor) : null,
      roomId,
      postDebatePoll: { pro: 0, con: 0, tie: 0, voters: [] },
      postDebateScores: [],
      comments: [],
      noShowPenalty: false,
    });
    await topic.save();
    io.emit('refresh-topics');
    res.json(topic);
  } catch (err) {
    console.error('Create topic error:', err);
    res.status(500).json({ error: 'Server error creating topic' });
  }
});

// Join topic as role - updated to support team sides
app.post('/topics/:id/join', async (req, res) => {
  try {
    const { user, role, userStance } = req.body;
    const topic = await Topic.findById(req.params.id);
    if (!topic) return res.status(404).json({ error: 'Topic not found' });

    // check scheduled
    if (role === 'creator' && user !== topic.creator) {
      return res.status(400).json({ error: 'Only creator can enter as creator' });
    }
    if (topic.scheduledFor && new Date() < topic.scheduledFor) {
      return res.status(400).json({ error: 'Debate not started yet' });
    }

    if (role === 'creator') {
      // creator simply enters
    } else if (role === 'opponent') {
      // userStance expected to be 'pro' or 'con' (opposite of creator)
      const allowedSide = (userStance === 'pro' || userStance === 'con') ? userStance : (topic.creatorStance === 'pro' ? 'con' : 'pro');
      // limit per side to 3 (you wanted 2-3; we'll allow up to 3)
      const sideCount = topic.opponents.filter(o => o.side === allowedSide).length;
      if (topic.creator === user) return res.status(400).json({ error: 'Cannot join your own topic as opponent' });
      if (sideCount >= 3) return res.status(400).json({ error: `Team full for ${allowedSide}` });
      // ensure not already in opponents
      if (topic.opponents.some(o => o.email === user)) return res.status(400).json({ error: 'Already joined' });
      topic.opponents.push({ side: allowedSide, email: user });
    } else if (role === 'mediator') {
      if (topic.mediator && topic.mediator !== user) return res.status(400).json({ error: 'Mediator already assigned' });
      topic.mediator = user;
    } else if (role === 'viewer') {
      // viewers don't change topic model
    } else {
      return res.status(400).json({ error: 'Invalid role' });
    }

    await topic.save();
    io.emit('refresh-topics'); // so frontend updates counts
    res.json({ roomId: topic.roomId, creatorStance: topic.creatorStance });
  } catch (err) {
    console.error('Join topic error:', err);
    res.status(500).json({ error: 'Server error joining topic' });
  }
});

// Delete topic
app.delete('/topics/:id', async (req, res) => {
  try {
    const { user } = req.body;
    const topic = await Topic.findById(req.params.id);
    if (!topic) return res.status(404).json({ error: 'Topic not found' });
    if (topic.creator !== user) return res.status(403).json({ error: 'Only creator can delete' });
    await Topic.findByIdAndDelete(req.params.id);
    io.emit('refresh-topics');
    res.json({ success: true });
  } catch (err) {
    console.error('Delete topic error:', err);
    res.status(500).json({ error: 'Server error deleting topic' });
  }
});

// Comment (forum) — nested comments supported
app.post('/topics/:id/comment', async (req, res) => {
  try {
    const { user, text, parentId } = req.body;
    const topic = await Topic.findById(req.params.id);
    if (!topic) return res.status(404).json({ error: 'Topic not found' });
    topic.comments.push({ author: user, text, parentId: parentId || null, timestamp: new Date() });
    await topic.save();
    io.emit('refresh-topics');
    res.json({ success: true });
  } catch (err) {
    console.error('Comment error:', err);
    res.status(500).json({ error: 'Server error adding comment' });
  }
});

// Start debate from comment — creates a new topic seeded from a comment
app.post('/topics/:id/start-debate', async (req, res) => {
  try {
    const { user, parentCommentId } = req.body;
    const srcTopic = await Topic.findById(req.params.id);
    if (!srcTopic) return res.status(404).json({ error: 'Topic not found' });
    const parentComment = srcTopic.comments.find(c => String(c._id) === String(parentCommentId));
    if (!parentComment) return res.status(404).json({ error: 'Comment not found' });

    const newTitle = `Debate from comment on ${srcTopic.title}`;
    const newDescription = parentComment.text;
    // description must be >=50 words — ensure it's long enough; otherwise reject
    if (countWords(newDescription) < 50) {
      return res.status(400).json({ error: 'The comment is too short to start a debate (needs min 50 words)' });
    }

    const roomId = Math.random().toString(36).substring(2, 10);
    const newTopic = new Topic({
      title: newTitle,
      description: newDescription,
      category: srcTopic.category,
      creatorStance: 'pro',
      creator: user,
      opponents: [],
      mediator: null,
      scheduledFor: null,
      roomId,
      postDebatePoll: { pro: 0, con: 0, tie: 0, voters: [] },
      postDebateScores: [],
      comments: [],
      noShowPenalty: false,
    });
    await newTopic.save();
    io.emit('refresh-topics');
    res.json(newTopic);
  } catch (err) {
    console.error('Start debate error:', err);
    res.status(500).json({ error: 'Server error starting debate' });
  }
});

// Poll voting (post-debate simple poll: pro/con/tie)
app.post('/topics/:id/poll', async (req, res) => {
  try {
    const { user, vote } = req.body; // vote: 'pro'|'con'|'tie'
    const topic = await Topic.findById(req.params.id);
    if (!topic) return res.status(404).json({ error: 'Topic not found' });

    // do not allow duplicate poll votes from same user
    if (topic.postDebatePoll.voters.includes(user)) return res.status(400).json({ error: 'Already voted in poll' });

    if (vote === 'pro') topic.postDebatePoll.pro += 1;
    else if (vote === 'con') topic.postDebatePoll.con += 1;
    else topic.postDebatePoll.tie += 1;

    topic.postDebatePoll.voters.push(user);
    await topic.save();

    io.to(topic.roomId).emit('poll-updated', { topicId: topic._id, postDebatePoll: topic.postDebatePoll });
    res.json({ success: true, postDebatePoll: topic.postDebatePoll });
  } catch (err) {
    console.error('Poll error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Submit detailed post-debate scores (eligible per your rules)
app.post('/topics/:id/score', async (req, res) => {
  /*
    Body:
    {
      scorer: "user@example.com",
      role: "viewer" | "debater" | "mediator",
      scores: { "<targetEmail>": { logic: 4, civility: 5 }, ... }
    }
  */
  try {
    const { scorer, role, scores } = req.body;
    const topic = await Topic.findById(req.params.id);
    if (!topic) return res.status(404).json({ error: 'Topic not found' });

    // Eligibility checks:
    // - viewer can score mediator & debaters
    // - debater can score other debaters only
    // - mediator can score debaters only
    // We'll accept the scores object but do a validation pass
    const allowedTargets = new Set();
    // all debaters: creator + opponents emails
    const debaters = new Set([topic.creator, ...topic.opponents.map(o => o.email).filter(Boolean)]);
    if (topic.mediator) allowedTargets.add(topic.mediator);
    debaters.forEach(d => allowedTargets.add(d));

    const invalidTargets = [];
    for (const target of Object.keys(scores || {})) {
      // ensure target is allowed based on role
      if (role === 'viewer') {
        // viewer allowed to score mediator and debaters (so OK if target in allowedTargets)
        if (!allowedTargets.has(target)) invalidTargets.push(target);
      } else if (role === 'debater') {
        // find if scorer is a debater
        if (!debaters.has(scorer)) return res.status(400).json({ error: 'Scorer not recognized as debater' });
        if (!debaters.has(target) || target === scorer) invalidTargets.push(target); // cannot score self
      } else if (role === 'mediator') {
        if (topic.mediator !== scorer) return res.status(400).json({ error: 'Scorer not mediator' });
        if (!debaters.has(target)) invalidTargets.push(target);
      } else {
        return res.status(400).json({ error: 'Invalid role for scoring' });
      }
    }

    if (invalidTargets.length > 0) {
      return res.status(400).json({ error: 'Invalid score targets', invalidTargets });
    }

    // Save the score record
    topic.postDebateScores.push({ scorer, role, scores });
    await topic.save();

    // Optionally: after some threshold (or manually) apply aggregated scores to points;
    // for simplicity, we can call applyPostDebateScores when topic ends or when enough scores exist.
    io.to(topic.roomId).emit('scores-updated', { topicId: topic._id, postDebateScores: topic.postDebateScores });
    res.json({ success: true });
  } catch (err) {
    console.error('Score submission error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// End debate endpoint (to be called when debate finishes)
app.post('/topics/:id/end', async (req, res) => {
  try {
    const { user } = req.body;
    const topic = await Topic.findById(req.params.id);
    if (!topic) return res.status(404).json({ error: 'Topic not found' });

    // Only creator or mediator may end (or allow anyone); we'll permit creator or mediator
    if (user !== topic.creator && user !== topic.mediator) {
      return res.status(403).json({ error: 'Only creator or mediator can end the debate' });
    }

    topic.endedAt = new Date();
    await topic.save();

    // Apply poll results to assign winner or tie and optionally update points
    // Simple logic: determine winner by postDebatePoll totals
    const poll = topic.postDebatePoll || { pro: 0, con: 0, tie: 0 };
    let winner = 'tie';
    if (poll.pro > poll.con) winner = 'pro';
    else if (poll.con > poll.pro) winner = 'con';
    // update points: winner side participants gain +10, losers -5 (example)
    const winnerBonus = 10;
    const loserPenalty = 5;
    if (winner === 'pro' || winner === 'con') {
      // apply to each debater on respective side
      const proDebaters = [topic.creator, ...topic.opponents.filter(o => o.side === 'pro').map(o => o.email)];
      const conDebaters = topic.opponents.filter(o => o.side === 'con').map(o => o.email);
      if (winner === 'pro') {
        for (const e of proDebaters) {
          const u = await User.findOne({ email: e });
          if (u) { u.points = (u.points || 0) + winnerBonus; await u.save(); }
        }
        for (const e of conDebaters) {
          const u = await User.findOne({ email: e });
          if (u) { u.points = Math.max(0, (u.points || 0) - loserPenalty); await u.save(); }
        }
      } else {
        for (const e of conDebaters) {
          const u = await User.findOne({ email: e });
          if (u) { u.points = (u.points || 0) + winnerBonus; await u.save(); }
        }
        for (const e of proDebaters) {
          const u = await User.findOne({ email: e });
          if (u) { u.points = Math.max(0, (u.points || 0) - loserPenalty); await u.save(); }
        }
      }
    }
    // apply detailed scores (aggregated) to points
    await applyPostDebateScores(topic._id);

    io.to(topic.roomId).emit('debate-ended', { topicId: topic._id, winner });
    io.emit('refresh-topics');
    res.json({ success: true, winner });
  } catch (err) {
    console.error('End debate error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// No-show penalty check (improved)
// This endpoint can be polled/right-after scheduled time to deduct points when required
app.post('/topics/:id/check-no-show', async (req, res) => {
  try {
    const { user, role } = req.body;
    const topic = await Topic.findById(req.params.id);
    if (!topic) return res.status(404).json({ error: 'Topic not found' });

    const now = new Date();
    if (!topic.scheduledFor) return res.json({ penalty: false });

    // If now is more than scheduled time + 5 minutes and penalty not applied, check slots
    const fiveMinLater = new Date(topic.scheduledFor.getTime() + 5 * 60 * 1000);
    if (now > fiveMinLater && !topic.noShowPenalty) {
      // If creator and no opponents showed up -> penalty to creator
      const proDebaters = [topic.creator, ...topic.opponents.filter(o => o.side === 'pro').map(o => o.email)];
      const conDebaters = topic.opponents.filter(o => o.side === 'con').map(o => o.email);
      // Example rule: if any required role missing (creator or at least 1 opponent), penalize missing user(s)
      const penalties = [];
      // If creator didn't show? Hard to detect automatically, but we expect creator to be tied to a socket presence.
      // We'll assume front-end will call check-no-show with role and user identity.
      if (role === 'creator') {
        // if no opponents joined at scheduled time -> penalize creator
        if (topic.opponents.length === 0) {
          const cu = await User.findOne({ email: topic.creator });
          if (cu) { cu.points = Math.max(0, cu.points - 10); await cu.save(); }
          topic.noShowPenalty = true;
          await topic.save();
          penalties.push(topic.creator);
        }
      } else if (role === 'opponent') {
        // if an opponent signed up but didn't appear, front-end should call this and we deduct
        const oppUser = await User.findOne({ email: user });
        if (oppUser) { oppUser.points = Math.max(0, oppUser.points - 10); await oppUser.save(); }
        topic.noShowPenalty = true;
        await topic.save();
        penalties.push(user);
      }
      io.emit('refresh-topics');
      return res.json({ penalty: true, penalties });
    }
    return res.json({ penalty: false });
  } catch (err) {
    console.error('check-no-show error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ------------------ Socket.IO (real-time controls) ------------------
// ------------------ Socket.IO (real-time controls) ------------------
io.on('connection', (socket) => {
  const userEmail = socket.handshake.query.userId;
  console.log(`User connected: ${userEmail}, socket: ${socket.id}`);

  // When user joins a debate room
  socket.on('join-room', (roomId, userEmail, role) => {
    socket.join(roomId);
    socket.data = { roomId, userEmail, role };
    socket.to(roomId).emit('user-connected', { userId: userEmail, role });
    io.emit('refresh-topics');
  });

  // Video call + chat
  socket.on('peer-id', (roomId, peerId, userEmail, role) => {
    socket.to(roomId).emit('peer-id', { peerId, userId: userEmail, role });
  });

  socket.on('chat-message', (roomId, msg) => {
    io.to(roomId).emit('chat-message', msg);
  });

  socket.on('qa-message', (roomId, qa) => {
    io.to(roomId).emit('qa-message', qa);
  });

  // Mediator controls
  socket.on('mute-user', ({ roomId, targetUser }) => {
    socket.to(roomId).emit('mute-user', targetUser);
  });

  socket.on('unmute-user', ({ roomId, targetUser }) => {
    socket.to(roomId).emit('unmute-user', targetUser);
  });

  socket.on('approve-qa', ({ roomId, qaId }) => {
    socket.to(roomId).emit('approve-qa', qaId);
  });

  // Handle disconnect — free up slots properly
  socket.on('disconnect', async () => {
    const { roomId, userEmail, role } = socket.data || {};
    if (!roomId || !userEmail) return;

    try {
      const topic = await Topic.findOne({ roomId });
      if (!topic) return;

      let changed = false;

      // Remove user from opponents if present
      if (topic.opponents.some(o => o.email === userEmail)) {
        topic.opponents = topic.opponents.filter(o => o.email !== userEmail);
        io.to(roomId).emit('slot-cleared', { role: 'opponent', user: userEmail });
        changed = true;
      }

      // Clear mediator if they left
      if (topic.mediator === userEmail) {
        topic.mediator = null;
        io.to(roomId).emit('slot-cleared', { role: 'mediator', user: userEmail });
        changed = true;
      }

      if (changed) {
        await topic.save();
        io.emit('refresh-topics');
      }

      console.log(`User disconnected: ${userEmail} from room ${roomId}`);
    } catch (err) {
      console.error('Error handling disconnect:', err);
    }
  });
});

// ------------------ Start server ------------------
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
