// server/controllers/adminController.js
const Comment = require("../models/commentModels");
const User = require("../models/userModels");
const Blog = require("../models/blogModel");
const AuditLog = require("../models/auditLogModel");

// Delete any comment (Admin only)
exports.deleteAnyComment = async (req, res) => {
  try {
    const comment = await Comment.findById(req.params.id);
    if (!comment) {
      return res.status(404).json({ 
        status: 'fail',
        message: "Comment not found" 
      });
    }

    // ✅ FIXED: Use req.user.id instead of req.user._id
    await AuditLog.create({
      action: "DELETE_COMMENT",
      targetId: comment._id,
      performedBy: req.user.id, // ✅ Changed from req.user._id
      metadata: {
        contentPreview: comment.content.substring(0, 50) + (comment.content.length > 50 ? "..." : ""),
        blogId: comment.blog
      }
    });

    // Remove comment reference from blog
    if (!comment.parentComment) {
      await Blog.findByIdAndUpdate(comment.blog, {
        $pull: { comments: comment._id }
      });
    } else {
      // Remove from parent comment's replies
      await Comment.findByIdAndUpdate(comment.parentComment, {
        $pull: { replies: comment._id }
      });
    }

    // Delete all replies recursively
    if (comment.replies && comment.replies.length > 0) {
      await Comment.deleteMany({ _id: { $in: comment.replies } });
    }

    await comment.deleteOne();

    res.status(200).json({ 
      status: 'success',
      message: "Comment deleted by Admin", 
      data: {
        commentId: comment._id 
      }
    });
  } catch (error) {
    console.error("Admin Comment Deletion Error:", error.message);
    res.status(500).json({
      status: 'error',
      message: "Server Error",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

// Promote user to moderator
exports.makeModerator = async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ 
        status: 'fail',
        message: "User not found" 
      });
    }

    if (user.role === "moderator") {
      return res.status(400).json({
        status: 'fail',
        message: "User is already a moderator",
        data: {
          userId: user._id
        }
      });
    }

    const previousRole = user.role;
    user.role = "moderator";

    // ✅ FIXED: Use req.user.id instead of req.user._id
    await AuditLog.create({
      action: "ROLE_CHANGE",
      targetId: user._id,
      performedBy: req.user.id, // ✅ Changed from req.user._id
      metadata: {
        from: previousRole,
        to: "moderator"
      }
    });

    await user.save();

    res.status(200).json({
      status: 'success',
      message: `${user.username} promoted to moderator`,
      data: {
        user: {
          id: user._id,
          username: user.username,
          role: user.role
        }
      }
    });
  } catch (error) {
    console.error("Role Promotion Error:", error.message);
    res.status(500).json({
      status: 'error',
      message: "Server Error",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

// Demote moderator to user
exports.demoteModerator = async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ 
        status: 'fail',
        message: "User not found" 
      });
    }

    if (user.role === "user") {
      return res.status(400).json({
        status: 'fail',
        message: "User is already a regular user"
      });
    }

    const previousRole = user.role;
    user.role = "user";

    await AuditLog.create({
      action: "ROLE_CHANGE",
      targetId: user._id,
      performedBy: req.user.id,
      metadata: {
        from: previousRole,
        to: "user"
      }
    });

    await user.save();

    res.status(200).json({
      status: 'success',
      message: `${user.username} demoted to user`,
      data: {
        user: {
          id: user._id,
          username: user.username,
          role: user.role
        }
      }
    });
  } catch (error) {
    console.error("Role Demotion Error:", error.message);
    res.status(500).json({
      status: 'error',
      message: "Server Error",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

// Get all reported comments
exports.getReportedComments = async (req, res) => {
  try {
    const comments = await Comment.find({ 
      reportedCount: { $gt: 0 } 
    })
      .populate('user', 'username email')
      .populate('blog', 'title')
      .sort('-reportedCount')
      .lean();

    res.status(200).json({
      status: 'success',
      count: comments.length,
      data: {
        comments
      }
    });
  } catch (error) {
    console.error("Get Reported Comments Error:", error.message);
    res.status(500).json({
      status: 'error',
      message: "Server Error",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

// Mark comment as spam or not spam
exports.toggleCommentSpam = async (req, res) => {
  try {
    const comment = await Comment.findById(req.params.id);
    if (!comment) {
      return res.status(404).json({
        status: 'fail',
        message: "Comment not found"
      });
    }

    comment.isSpam = !comment.isSpam;
    await comment.save();

    await AuditLog.create({
      action: comment.isSpam ? "MARK_SPAM" : "UNMARK_SPAM",
      targetId: comment._id,
      performedBy: req.user.id,
      metadata: {
        contentPreview: comment.content.substring(0, 50)
      }
    });

    res.status(200).json({
      status: 'success',
      message: comment.isSpam ? "Comment marked as spam" : "Comment unmarked as spam",
      data: {
        comment
      }
    });
  } catch (error) {
    console.error("Toggle Spam Error:", error.message);
    res.status(500).json({
      status: 'error',
      message: "Server Error",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

// Bulk delete spam comments
exports.deleteSpamComments = async (req, res) => {
  try {
    const result = await Comment.deleteMany({ isSpam: true });

    await AuditLog.create({
      action: "BULK_DELETE_SPAM",
      performedBy: req.user.id,
      metadata: {
        deletedCount: result.deletedCount
      }
    });

    res.status(200).json({
      status: 'success',
      message: `Deleted ${result.deletedCount} spam comments`,
      data: {
        deletedCount: result.deletedCount
      }
    });
  } catch (error) {
    console.error("Bulk Delete Spam Error:", error.message);
    res.status(500).json({
      status: 'error',
      message: "Server Error",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};