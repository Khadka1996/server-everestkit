// Dashboard data: overview stats, notifications, audit log and comment lists.
const mongoose = require('mongoose');
const User = require('../models/userModels');
const Blog = require('../models/blogModel');
const Comment = require('../models/commentModels');
const Message = require('../models/messageModel');
const Client = require('../models/clientModel');
const Service = require('../models/serviceModal');
const Advertisement = require('../models/adsModel');
const AuditLog = require('../models/auditLogModel');
const { ChatMessage, Device } = require('../models/chatModel');
const { logger } = require('../utils/logger.util');

const DAY = 24 * 60 * 60 * 1000;
const escapeRegex = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const pageParams = (q, defLimit = 20) => {
  const limit = Math.min(100, Math.max(1, parseInt(q.limit, 10) || defLimit));
  const page = Math.max(1, parseInt(q.page, 10) || 1);
  return { limit, page, skip: (page - 1) * limit };
};

// Count documents per day for the last `days` days -> [{ date: 'YYYY-MM-DD', count }]
const dailyCounts = async (Model, days, match = {}) => {
  const since = new Date(Date.now() - (days - 1) * DAY);
  since.setHours(0, 0, 0, 0);
  const rows = await Model.aggregate([
    { $match: { ...match, createdAt: { $gte: since } } },
    { $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } }, count: { $sum: 1 } } },
  ]);
  const byDay = Object.fromEntries(rows.map((r) => [r._id, r.count]));
  return Array.from({ length: days }, (_, i) => {
    const d = new Date(since.getTime() + i * DAY).toISOString().slice(0, 10);
    return { date: d, count: byDay[d] || 0 };
  });
};

// GET /api/admin/overview?days=7|30
exports.getOverview = async (req, res) => {
  try {
    const days = [7, 14, 30, 90].includes(Number(req.query.days)) ? Number(req.query.days) : 7;
    const now = Date.now();
    const weekAgo = new Date(now - 7 * DAY);
    const dayAgo = new Date(now - DAY);
    const isAdmin = req.user.role === 'admin';

    const [
      users, admins, moderators, newUsers,
      blogs, publishedBlogs, blogTotals, topBlogs, latestBlogs,
      comments, reportedComments, spamComments,
      messages, newMessages, latestMessages,
      unreadChats, activeDevices,
      clients, clientProjects,
      services, activeServices,
      ads,
      usersSeries, messagesSeries, commentsSeries,
      recentLogs,
    ] = await Promise.all([
      User.countDocuments(),
      User.countDocuments({ role: 'admin' }),
      User.countDocuments({ role: 'moderator' }),
      User.countDocuments({ createdAt: { $gte: weekAgo } }),

      Blog.countDocuments(),
      Blog.countDocuments({ isPublished: { $ne: false } }),
      Blog.aggregate([{ $group: { _id: null, views: { $sum: { $ifNull: ['$viewCount', 0] } }, likes: { $sum: { $size: { $ifNull: ['$likes', []] } } }, shares: { $sum: { $ifNull: ['$shareCount', 0] } } } }]),
      Blog.find({}, 'title viewCount createdAt').sort({ viewCount: -1 }).limit(5).lean(),
      Blog.find({}, 'title viewCount createdAt').sort({ createdAt: -1 }).limit(5).lean(),

      Comment.countDocuments(),
      Comment.countDocuments({ reportedCount: { $gt: 0 }, isSpam: { $ne: true } }),
      Comment.countDocuments({ isSpam: true }),

      Message.countDocuments(),
      Message.countDocuments({ status: 'new' }),
      Message.find({}, 'name email service status createdAt').sort({ createdAt: -1 }).limit(5).lean(),

      ChatMessage.countDocuments({ senderType: 'guest', read: false }),
      Device.countDocuments({ lastActive: { $gte: dayAgo }, isBlocked: { $ne: true } }),

      Client.countDocuments(),
      Client.aggregate([{ $group: {
        _id: null,
        completed: { $sum: { $cond: ['$project.completed', 1, 0] } },
        budget: { $sum: { $ifNull: ['$project.budget', 0] } },
        overdue: { $sum: { $cond: [{ $and: [{ $not: ['$project.completed'] }, { $lt: ['$project.deadline', new Date()] }] }, 1, 0] } },
      } }]),

      Service.countDocuments(),
      Service.countDocuments({ isActive: { $ne: false } }),

      Advertisement.aggregate([{ $group: {
        _id: null,
        total: { $sum: 1 },
        active: { $sum: { $cond: ['$isActive', 1, 0] } },
        impressions: { $sum: '$impressions' },
        clicks: { $sum: '$clicks' },
      } }]),

      dailyCounts(User, days),
      dailyCounts(Message, days),
      dailyCounts(Comment, days),

      isAdmin
        ? AuditLog.find({}, 'action metadata createdAt performedBy targetModel').populate('performedBy', 'username email').sort({ createdAt: -1 }).limit(8).lean()
        : Promise.resolve([]),
    ]);

    const bt = blogTotals[0] || {};
    const cp = clientProjects[0] || {};
    const ad = ads[0] || {};

    res.status(200).json({
      success: true,
      data: {
        users: { total: users, admins, moderators, newThisWeek: newUsers },
        blogs: { total: blogs, published: publishedBlogs, views: bt.views || 0, likes: bt.likes || 0, shares: bt.shares || 0, top: topBlogs, latest: latestBlogs },
        comments: { total: comments, reported: reportedComments, spam: spamComments },
        messages: { total: messages, new: newMessages, latest: latestMessages },
        chat: { unread: unreadChats, activeDevices },
        clients: { total: clients, completed: cp.completed || 0, active: clients - (cp.completed || 0), overdue: cp.overdue || 0, budget: cp.budget || 0 },
        services: { total: services, active: activeServices },
        ads: {
          total: ad.total || 0, active: ad.active || 0, impressions: ad.impressions || 0, clicks: ad.clicks || 0,
          ctr: ad.impressions ? Number(((ad.clicks / ad.impressions) * 100).toFixed(2)) : 0,
        },
        series: { days, users: usersSeries, messages: messagesSeries, comments: commentsSeries },
        recentActivity: recentLogs,
        generatedAt: new Date().toISOString(),
      },
    });
  } catch (error) {
    logger.error(`Admin overview failed: ${error.message}`);
    res.status(500).json({ success: false, message: 'Could not load dashboard overview' });
  }
};

// GET /api/admin/notifications — lightweight counts for the sidebar badges and the header bell.
exports.getNotifications = async (req, res) => {
  try {
    const [newMessages, unreadChats, reportedComments, latestMessages, latestReported] = await Promise.all([
      Message.countDocuments({ status: 'new' }),
      ChatMessage.countDocuments({ senderType: 'guest', read: false }),
      Comment.countDocuments({ reportedCount: { $gt: 0 }, isSpam: { $ne: true } }),
      Message.find({ status: 'new' }, 'name service createdAt').sort({ createdAt: -1 }).limit(5).lean(),
      Comment.find({ reportedCount: { $gt: 0 }, isSpam: { $ne: true } }, 'content reportedCount createdAt').sort({ updatedAt: -1 }).limit(5).lean(),
    ]);

    const items = [
      ...latestMessages.map((m) => ({
        id: `msg-${m._id}`, type: 'message', title: `New message from ${m.name || 'a visitor'}`,
        description: m.service ? `About: ${m.service}` : 'Contact form', href: `/dashboard/messages/${m._id}`, time: m.createdAt,
      })),
      ...latestReported.map((c) => ({
        id: `cmt-${c._id}`, type: 'comment', title: `Comment reported ${c.reportedCount}×`,
        description: String(c.content || '').slice(0, 80), href: '/dashboard/comments/reported', time: c.createdAt,
      })),
    ].sort((a, b) => new Date(b.time) - new Date(a.time));

    if (unreadChats > 0) {
      items.unshift({
        id: `chat-${unreadChats}`, type: 'chat', title: `${unreadChats} unread live chat message${unreadChats > 1 ? 's' : ''}`,
        description: 'Visitors are waiting for a reply', href: '/dashboard/chat', time: new Date(),
      });
    }

    res.status(200).json({
      success: true,
      data: { counts: { messages: newMessages, liveChats: unreadChats, reportedComments }, items: items.slice(0, 10) },
    });
  } catch (error) {
    logger.error(`Notifications failed: ${error.message}`);
    res.status(500).json({ success: false, message: 'Could not load notifications' });
  }
};

// GET /api/admin/audit-logs?page&limit&action&search
exports.getAuditLogs = async (req, res) => {
  try {
    const { limit, page, skip } = pageParams(req.query, 25);
    const query = {};
    if (req.query.action) query.action = String(req.query.action);
    if (req.query.search) {
      const rx = new RegExp(escapeRegex(req.query.search), 'i');
      const users = await User.find({ $or: [{ email: rx }, { username: rx }] }, '_id').limit(50).lean();
      query.$or = [{ performedBy: { $in: users.map((u) => u._id) } }, { ipAddress: rx }];
    }
    const [logs, total, actions] = await Promise.all([
      AuditLog.find(query).populate('performedBy', 'username email role').sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
      AuditLog.countDocuments(query),
      AuditLog.distinct('action'),
    ]);
    res.status(200).json({ success: true, data: { logs, total, page, limit, actions: actions.sort() } });
  } catch (error) {
    logger.error(`Audit logs failed: ${error.message}`);
    res.status(500).json({ success: false, message: 'Could not load audit logs' });
  }
};

// GET /api/admin/comments?page&limit&search&status=all|reported|spam|replies
exports.getComments = async (req, res) => {
  try {
    const { limit, page, skip } = pageParams(req.query, 20);
    const query = {};
    const status = req.query.status || 'all';
    if (status === 'reported') Object.assign(query, { reportedCount: { $gt: 0 }, isSpam: { $ne: true } });
    if (status === 'spam') query.isSpam = true;
    if (status === 'clean') Object.assign(query, { isSpam: { $ne: true }, reportedCount: { $in: [0, null] } });
    if (req.query.search) query.content = new RegExp(escapeRegex(req.query.search), 'i');
    if (req.query.blog && mongoose.isValidObjectId(req.query.blog)) query.blog = req.query.blog;

    const [comments, total] = await Promise.all([
      Comment.find(query)
        .populate('user', 'username email')
        .populate('blog', 'title')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      Comment.countDocuments(query),
    ]);

    res.status(200).json({
      success: true,
      data: {
        comments: comments.map((c) => ({ ...c, likesCount: c.likes?.length || 0, repliesCount: c.replies?.length || 0, likes: undefined, replies: undefined })),
        total, page, limit,
      },
    });
  } catch (error) {
    logger.error(`Admin comments failed: ${error.message}`);
    res.status(500).json({ success: false, message: 'Could not load comments' });
  }
};
