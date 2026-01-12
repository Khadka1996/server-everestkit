const express = require('express');
const router = express.Router();
const blogController = require('../controllers/blogController');
const blogMiddleware = require('../middlewares/blogMiddleware');
const { authMiddleware } = require('../middlewares/authMiddleware.js');

// Public routes
router.get('/', blogController.getAllBlogs);
router.get("/latest", blogController.getLatestArticles);
router.get("/top-viewed", blogController.getTopViewedArticle);
router.get('/top', blogController.getTopArticle);
router.get('/:id', blogController.getBlog);
router.get('/:id/comments', blogController.getBlogComments);

// Protected routes (require authentication)
router.use(authMiddleware);

router.post('/:id/like', blogController.likeBlog);
router.post('/', blogMiddleware.uploadBlogImage, blogMiddleware.handleUploadErrors, blogMiddleware.validateBlogData, blogController.createBlog);
router.patch('/:id', blogMiddleware.uploadBlogImage, blogMiddleware.handleUploadErrors, blogController.updateBlog);
router.delete('/:id', blogController.deleteBlog);

// Comment routes
router.post('/:id/comments', blogController.addComment);
router.post('/comments/:id/like', blogController.likeComment);
router.post('/comments/:id/report', blogController.reportComment);
router.delete('/comments/:id', blogController.deleteComment);

module.exports = router;