// server/controllers/blogController.js (WITH REDIS)
const Blog = require('../models/blogModel');
const Comment = require('../models/commentModels');
const fs = require('fs');
const path = require('path');
const { promisify } = require('util');
const unlinkAsync = promisify(fs.unlink);
const he = require('he');
const redisCache = require('../utils/redisCache'); 
// Helper to delete file
const deleteFile = async (filePath) => {
  try {
    await unlinkAsync(path.join(__dirname, '../uploads', filePath));
  } catch (err) {
    console.error('Error deleting file:', err.message);
  }
};

// ==================== BLOG CRUD OPERATIONS ====================

const createBlog = async (req, res) => {
  try {
    console.log('createBlog received:', {
      body: req.body,
      file: req.file,
      headers: req.headers,
    });

    const { title, content, youtubeLink, subheading, tags } = req.body;

    if (!title || !content) {
      if (req.file) await fs.unlink(path.join(__dirname, '../uploads', req.file.filename));
      return res.status(400).json({
        success: false,
        error: 'Title and content are required',
      });
    }

    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: 'Featured image is required',
      });
    }

    const blog = await Blog.create({
      title,
      content,
      youtubeLink,
      subheading,
      tags: Array.isArray(tags) ? tags : tags ? tags.split(',') : [],
      image: req.file.filename,
    });

    // ✅ Invalidate cache
    await redisCache.delPattern('blogs:*');

    console.log('Blog created successfully:', blog._id);
    res.status(201).json({
      success: true,
      data: blog,
    });
  } catch (err) {
    console.error('createBlog error:', err);
    if (req.file) await fs.unlink(path.join(__dirname, '../uploads', req.file.filename));
    res.status(500).json({
      success: false,
      error: 'Internal server error',
    });
  }
};

const getAllBlogs = async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 12;
    const skip = (page - 1) * limit;
    const searchQuery = req.query.search || '';

    // ✅ Create cache key
    const cacheKey = `blogs:list:${page}:${limit}:${searchQuery}`;

    // ✅ Try to get from cache
    const cachedData = await redisCache.get(cacheKey);
    if (cachedData) {
      console.log('📦 Serving blogs from Redis cache');
      return res.status(200).json(cachedData);
    }

    // Sanitize search input
    const sanitizeRegex = (input) => input.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const sanitizedSearchQuery = sanitizeRegex(searchQuery);

    const query = { isPublished: true };
    if (sanitizedSearchQuery) {
      query.$or = [
        { title: { $regex: sanitizedSearchQuery, $options: 'i' } },
        { content: { $regex: sanitizedSearchQuery, $options: 'i' } },
        { tags: { $regex: sanitizedSearchQuery, $options: 'i' } },
      ];
    }

    const total = await Blog.countDocuments(query);
    const blogs = await Blog.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const response = {
      success: true,
      count: blogs.length,
      total,
      data: blogs,
    };

    // ✅ Store in Redis cache for 5 minutes
    await redisCache.set(cacheKey, response, 300);

    res.status(200).json(response);
  } catch (err) {
    console.error('getAllBlogs error:', err);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
    });
  }
};

const getBlog = async (req, res) => {
  try {
    const blogId = req.params.id;
    const cacheKey = `blog:${blogId}`;

    // ✅ Try Redis cache first
    const cachedBlog = await redisCache.get(cacheKey);
    if (cachedBlog) {
      console.log('📦 Serving blog from Redis cache');
      return res.status(200).json({
        success: true,
        data: cachedBlog,
      });
    }

    // Fetch from database
    const blog = await Blog.findByIdAndUpdate(
      blogId,
      { $inc: { viewCount: 1 } },
      { new: true, lean: true }
    ).populate({
      path: 'comments',
      match: { isSpam: false },
      select: 'content user createdAt isEdited',
      populate: {
        path: 'user',
        select: 'username email'
      },
      options: { 
        lean: true,
        sort: { createdAt: -1 }
      },
    });

    if (!blog) {
      return res.status(404).json({
        success: false,
        error: 'Blog not found',
      });
    }

    const decodedContent = blog.content ? he.decode(blog.content) : blog.content;
    const blogData = { ...blog, content: decodedContent };

    // ✅ Store in Redis cache for 1 hour
    await redisCache.set(cacheKey, blogData, 3600);

    res.status(200).json({
      success: true,
      data: blogData,
    });
  } catch (err) {
    console.error('Error fetching blog:', err);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
    });
  }
};

const updateBlog = async (req, res) => {
  try {
    const { title, content, youtubeLink, subheading, tags } = req.body;
    
    const updateData = {
      title,
      content,
      youtubeLink,
      subheading,
      tags: Array.isArray(tags) ? tags : tags ? tags.split(',') : [],
    };

    if (req.file) {
      const existingBlog = await Blog.findById(req.params.id);
      if (existingBlog && existingBlog.image) {
        await deleteFile(existingBlog.image);
      }
      updateData.image = req.file.filename;
    }

    const updatedBlog = await Blog.findByIdAndUpdate(
      req.params.id, 
      updateData, 
      {
        new: true,
        runValidators: true,
      }
    );

    if (!updatedBlog) {
      if (req.file) await deleteFile(req.file.filename);
      return res.status(404).json({
        success: false,
        error: 'Blog not found',
      });
    }

    // ✅ Invalidate cache
    await redisCache.del(`blog:${req.params.id}`);
    await redisCache.delPattern('blogs:*');

    res.status(200).json({
      success: true,
      data: updatedBlog,
    });
  } catch (err) {
    console.error('updateBlog error:', err);
    if (req.file) await deleteFile(req.file.filename);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
    });
  }
};

const deleteBlog = async (req, res) => {
  try {
    const blog = await Blog.findById(req.params.id);
    if (!blog) {
      return res.status(404).json({
        success: false,
        error: 'Blog not found',
      });
    }

    if (blog.image) {
      await deleteFile(blog.image);
    }

    await Comment.deleteMany({ blog: req.params.id });
    await Blog.findByIdAndDelete(req.params.id);

    // ✅ Invalidate cache
    await redisCache.del(`blog:${req.params.id}`);
    await redisCache.delPattern('blogs:*');

    res.status(200).json({
      success: true,
      data: {},
    });
  } catch (err) {
    console.error('deleteBlog error:', err);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
    });
  }
};

// ==================== BLOG INTERACTION METHODS ====================

const getTopArticle = async (req, res) => {
  try {
    const cacheKey = 'blog:top';
    
    // ✅ Try cache first
    const cachedTop = await redisCache.get(cacheKey);
    if (cachedTop) {
      console.log('📦 Serving top article from cache');
      return res.status(200).json({
        success: true,
        data: cachedTop,
      });
    }

    const topArticle = await Blog.findOne({ isPublished: true })
      .sort({ viewCount: -1 })
      .limit(1)
      .lean();

    if (!topArticle) {
      return res.status(404).json({
        success: false,
        error: 'No articles found',
      });
    }

    // ✅ Cache for 10 minutes
    await redisCache.set(cacheKey, topArticle, 600);

    res.status(200).json({
      success: true,
      data: topArticle,
    });
  } catch (err) {
    console.error('getTopArticle error:', err);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
    });
  }
};

const likeBlog = async (req, res) => {
  try {
    console.log('Like request received:', {
      blogId: req.params.id,
      userId: req.user?.id
    });

    if (!req.user || !req.user.id) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required to like blogs',
      });
    }

    const blog = await Blog.findById(req.params.id);
    if (!blog) {
      return res.status(404).json({
        success: false,
        error: 'Blog not found',
      });
    }

    const userId = req.user.id;
    const likeIndex = blog.likes.findIndex(id => id.toString() === userId.toString());

    let message;
    let isLiked;

    if (likeIndex === -1) {
      blog.likes.push(userId);
      message = 'Blog liked successfully';
      isLiked = true;
    } else {
      blog.likes.splice(likeIndex, 1);
      message = 'Blog unliked successfully';
      isLiked = false;
    }
    
    await blog.save();

    // ✅ Invalidate cache
    await redisCache.del(`blog:${req.params.id}`);
    await redisCache.delPattern('blogs:*');

    res.status(200).json({
      success: true,
      data: {
        likeCount: blog.likes.length,
        isLiked: isLiked,
        message: message
      },
    });
  } catch (err) {
    console.error('likeBlog error:', err);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
    });
  }
};

// ==================== COMMENT METHODS ====================

const addComment = async (req, res) => {
  try {
    const { content } = req.body;

    if (!content || !content.trim()) {
      return res.status(400).json({
        success: false,
        error: 'Comment content is required',
      });
    }

    const blog = await Blog.findById(req.params.id);
    if (!blog) {
      return res.status(404).json({
        success: false,
        error: 'Blog not found',
      });
    }

    const comment = await Comment.create({
      content: content.trim(),
      blog: req.params.id,
      user: req.user.id,
    });

    await comment.populate('user', 'username email');

    await Blog.findByIdAndUpdate(req.params.id, {
      $push: { comments: comment._id },
    });

    // ✅ Invalidate cache
    await redisCache.del(`blog:${req.params.id}`);

    res.status(201).json({
      success: true,
      data: comment,
    });
  } catch (err) {
    console.error('addComment error:', err);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
    });
  }
};

const getBlogComments = async (req, res) => {
  try {
    const cacheKey = `comments:blog:${req.params.id}`;

    // ✅ Try cache
    const cachedComments = await redisCache.get(cacheKey);
    if (cachedComments) {
      console.log('📦 Serving comments from cache');
      return res.status(200).json(cachedComments);
    }

    const blog = await Blog.findById(req.params.id).populate({
      path: 'comments',
      match: { isSpam: false },
      select: 'content user createdAt isEdited likes',
      populate: [
        {
          path: 'user',
          select: 'username email'
        },
        {
          path: 'replies',
          match: { isSpam: false },
          populate: {
            path: 'user',
            select: 'username email'
          }
        }
      ],
      options: { 
        lean: true,
        sort: { createdAt: -1 }
      }
    });

    if (!blog) {
      return res.status(404).json({
        success: false,
        error: 'Blog not found',
      });
    }

    const response = {
      success: true,
      count: blog.comments.length,
      data: blog.comments,
    };

    // ✅ Cache for 5 minutes
    await redisCache.set(cacheKey, response, 300);

    res.status(200).json(response);
  } catch (err) {
    console.error('getBlogComments error:', err);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
    });
  }
};

const likeComment = async (req, res) => {
  try {
    const comment = await Comment.findById(req.params.id);
    if (!comment) {
      return res.status(404).json({
        success: false,
        error: 'Comment not found',
      });
    }

    const userId = req.user.id;
    const likeIndex = comment.likes.findIndex(id => id.toString() === userId.toString());

    let message;
    let isLiked;

    if (likeIndex === -1) {
      comment.likes.push(userId);
      message = 'Comment liked successfully';
      isLiked = true;
    } else {
      comment.likes.splice(likeIndex, 1);
      message = 'Comment unliked successfully';
      isLiked = false;
    }

    await comment.save();

    // ✅ Invalidate comments cache
    await redisCache.delPattern(`comments:blog:${comment.blog}`);

    res.status(200).json({
      success: true,
      data: {
        commentId: comment._id,
        likeCount: comment.likes.length,
        isLiked: isLiked,
        message: message
      },
    });
  } catch (err) {
    console.error('likeComment error:', err);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
    });
  }
};

const reportComment = async (req, res) => {
  try {
    const comment = await Comment.findById(req.params.id);
    if (!comment) {
      return res.status(404).json({
        success: false,
        error: 'Comment not found',
      });
    }

    comment.reportedCount += 1;

    const SPAM_THRESHOLD = 3;
    if (comment.reportedCount >= SPAM_THRESHOLD) {
      comment.isSpam = true;
    }

    await comment.save();

    // ✅ Invalidate cache
    await redisCache.delPattern(`comments:blog:${comment.blog}`);
    await redisCache.del(`blog:${comment.blog}`);

    res.status(200).json({
      success: true,
      data: {
        commentId: comment._id,
        reportedCount: comment.reportedCount,
        isSpam: comment.isSpam
      },
      message: comment.isSpam 
        ? 'Comment marked as spam due to multiple reports' 
        : 'Comment reported successfully',
    });
  } catch (err) {
    console.error('reportComment error:', err);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
    });
  }
};

const deleteComment = async (req, res) => {
  try {
    const comment = await Comment.findById(req.params.id);
    if (!comment) {
      return res.status(404).json({
        success: false,
        error: 'Comment not found',
      });
    }

    const isOwner = comment.user.toString() === req.user.id.toString();
    const isModerator = ['admin', 'moderator'].includes(req.user.role);

    if (!isOwner && !isModerator) {
      return res.status(403).json({
        success: false,
        error: 'Not authorized to delete this comment',
      });
    }

    if (!comment.parentComment) {
      await Blog.findByIdAndUpdate(comment.blog, {
        $pull: { comments: comment._id },
      });
    } else {
      await Comment.findByIdAndUpdate(comment.parentComment, {
        $pull: { replies: comment._id },
      });
    }

    if (comment.replies && comment.replies.length > 0) {
      await Comment.deleteMany({ _id: { $in: comment.replies } });
    }

    await comment.deleteOne();

    // ✅ Invalidate cache
    await redisCache.del(`blog:${comment.blog}`);
    await redisCache.delPattern(`comments:blog:${comment.blog}`);

    res.status(200).json({
      success: true,
      data: { id: req.params.id },
      message: 'Comment deleted successfully'
    });
  } catch (err) {
    console.error('deleteComment error:', err);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
    });
  }
};

const getTopViewedArticle = async (req, res) => {
  try {
    const cacheKey = 'blog:top-viewed';
    
    const cached = await redisCache.get(cacheKey);
    if (cached) {
      return res.status(200).json({ success: true, topArticle: cached });
    }

    const topArticle = await Blog.findOne({ isPublished: true })
      .sort('-viewCount')
      .lean();

    if (!topArticle) {
      return res.status(404).json({ 
        success: false, 
        message: 'No article found' 
      });
    }

    await redisCache.set(cacheKey, topArticle, 600);

    res.status(200).json({ success: true, topArticle });
  } catch (err) {
    console.error('Error fetching top article:', err);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
};

const getLatestArticles = async (req, res) => {
  try {
    const cacheKey = 'blogs:latest';
    
    const cached = await redisCache.get(cacheKey);
    if (cached) {
      return res.status(200).json(cached);
    }

    const blogs = await Blog.find({ isPublished: true })
      .sort('-createdAt')
      .limit(4)
      .lean();

    const response = {
      success: true,
      count: blogs.length,
      data: blogs,
    };

    await redisCache.set(cacheKey, response, 300);

    res.status(200).json(response);
  } catch (err) {
    console.error('getLatestArticles error:', err);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
    });
  }
};

module.exports = {
  createBlog,
  getAllBlogs,
  getBlog,
  updateBlog,
  deleteBlog,
  getTopArticle,
  likeBlog,
  addComment,
  getBlogComments,
  likeComment,
  reportComment,
  deleteComment,
  getTopViewedArticle,
  getLatestArticles
};