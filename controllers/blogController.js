const Blog = require("../models/blog");
const mongoose = require("mongoose");
const { APIError } = require("../utils/errorHandler");

// Create Blog
exports.createBlog = async (req, res, next) => {
  try {
    const { title, content } = req.body;
    const userId = req.user.id;

    if (!title || !content) {
      throw new APIError("Validation failed", 400, {
        title: !title ? "Title is required" : "",
        content: !content ? "Content is required" : "",
      });
    }

    const blog = new Blog({
      title: title.trim(),
      content: content.trim(),
      author: userId,
    });

    await blog.save();
    await blog.populate("author", "username");

    res.status(201).json({
      status: "success",
      data: blog,
      message: "Blog created successfully",
    });
  } catch (error) {
    next(error);
  }
};

// Get All Blogs with pagination
exports.getAllBlogs = async (req, res, next) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const [blogs, total] = await Promise.all([
      Blog.find()
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .populate("author", "username")
        .exec(),
      Blog.countDocuments(),
    ]);

    const hasMore = total > skip + blogs.length;

    res.json({
      status: "success",
      data: {
        blogs,
        hasMore,
        total,
        currentPage: page,
      },
    });
  } catch (error) {
    next(error);
  }
};

// Get User's Blogs with pagination
exports.getUserBlogs = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const [blogs, total] = await Promise.all([
      Blog.find({ author: userId })
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .populate("author", "username")
        .exec(),
      Blog.countDocuments({ author: userId }),
    ]);

    const hasMore = total > skip + blogs.length;

    res.json({
      status: "success",
      data: {
        blogs,
        hasMore,
        total,
        currentPage: page,
      },
    });
  } catch (error) {
    next(error);
  }
};

// Get Single Blog
exports.getBlogById = async (req, res) => {
  try {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ message: "Invalid blog ID" });
    }

    const blog = await Blog.findById(id).populate("author", "username");

    if (!blog) {
      return res.status(404).json({ message: "Blog not found" });
    }

    res.json(blog);
  } catch (error) {
    console.error("Get blog error:", error);
    res.status(500).json({ message: "Failed to fetch blog" });
  }
};

// Update Blog
exports.updateBlog = async (req, res) => {
  try {
    const { id } = req.params;
    const { title, content } = req.body;
    const userId = req.user.id;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ message: "Invalid blog ID" });
    }

    // Additional validation
    if (!title || !content) {
      return res.status(400).json({
        message: "Validation failed",
        errors: {
          title: !title ? "Title is required" : "",
          content: !content ? "Content is required" : "",
        },
      });
    }

    const blog = await Blog.findById(id);

    if (!blog) {
      return res.status(404).json({ message: "Blog not found" });
    }

    if (blog.author.toString() !== userId) {
      return res
        .status(403)
        .json({ message: "Not authorized to update this blog" });
    }

    blog.title = title.trim();
    blog.content = content.trim();
    blog.updatedAt = new Date();

    await blog.save();
    await blog.populate("author", "username");

    res.json(blog);
  } catch (error) {
    console.error("Update blog error:", error);
    res.status(500).json({ message: "Failed to update blog" });
  }
};

// Delete Blog
exports.deleteBlog = async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.id;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ message: "Invalid blog ID" });
    }

    const blog = await Blog.findById(id);

    if (!blog) {
      return res.status(404).json({ message: "Blog not found" });
    }

    if (blog.author.toString() !== userId) {
      return res
        .status(403)
        .json({ message: "Not authorized to delete this blog" });
    }

    await blog.deleteOne();
    res.json({ message: "Blog deleted successfully" });
  } catch (error) {
    console.error("Delete blog error:", error);
    res.status(500).json({ message: "Failed to delete blog" });
  }
};
