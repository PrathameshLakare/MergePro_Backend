const mongoose = require("mongoose");

const userSchema = mongoose.Schema(
  {
    githubUsername: { type: String, required: true, unique: true },
    avatarUrl: { type: String },
    bio: { type: String },
    customSlug: { type: String, unique: true },
    linkedinUrl: { type: String },
    portfolioUrl: { type: String },
    resumeUrl: { type: String },
    tags: [{ type: String }],
    featuredRepos: [
      {
        repoUrl: String,
        description: String,
      },
    ],
  },
  { timestamps: true }
);

const user = mongoose.model("user", userSchema);
module.exports = user;
