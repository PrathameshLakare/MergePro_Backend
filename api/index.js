require("dotenv").config();
const express = require("express");
const app = express();
const cors = require("cors");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const axios = require("axios");
const cloudinary = require("cloudinary");
const multer = require("multer");

const { setSecureCookie } = require("./services");
const { initializeDatabase } = require("./db/db.connect");
const User = require("./model/user.model");

app.use(express.json());
app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
  })
);
app.use(cookieParser());

const PORT = process.env.PORT || 5000;

const jwtSecret = process.env.JWT_SECRET;

initializeDatabase();

const verifyJwt = (req, res, next) => {
  const token = req.cookies["access_token"];
  if (!token) {
    return res.status(401).json({
      error: "Unauthorized",
      message: "GitHub authentication failed",
    });
  }

  try {
    const decodedToken = jwt.verify(token, jwtSecret);
    req.user = decodedToken;
    next();
  } catch (error) {
    res.status(403).json({ message: "Invalid token" });
  }
};

//cloudinary config
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const storage = multer.diskStorage({});

// const fileFilter = (req, file, cb) => {
//   if (file.mimetype === "application/pdf") {
//     cb(null, true);
//   } else {
//     cb(new Error("Only PDF files are allowed"), false);
//   }
// };

const upload = multer({
  storage,
  //fileFilter,
  // limits: {
  //   fileSize: 2 * 1024 * 1024,
  // },
});

//login with github auth
app.get("/v1/auth/github", (req, res) => {
  console.log(process.env.BACKEND_URL);
  const githubUrl = `https://github.com/login/oauth/authorize?client_id=${process.env.GITHUB_CLIENT_ID}&redirect_uri=${process.env.BACKEND_URL}/v1/auth/github/callback&scope=read:user`;
  res.redirect(githubUrl);
});

app.get("/v1/auth/github/callback", async (req, res) => {
  const code = req.query.code;

  if (!code) {
    return res.status(400).send(`Authorization code not provided.`);
  }

  try {
    const tokenResponse = await axios.post(
      "https://github.com/login/oauth/access_token",
      {
        client_id: process.env.GITHUB_CLIENT_ID,
        client_secret: process.env.GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: `${process.env.BACKEND_URL}/v1/auth/github/callback`,
      },
      {
        headers: {
          Accept: "application/json",
        },
      }
    );

    const accessToken = tokenResponse.data.access_token;

    const userRes = await axios.get("https://api.github.com/user", {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    const user = userRes.data;

    const jwtToken = jwt.sign(
      {
        login: user.login,
        access_token: accessToken,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "24h",
      }
    );
    setSecureCookie(res, jwtToken);
    return res.redirect(`${process.env.FRONTEND_URL}/home`);
  } catch (error) {
    console.error(error);
    res.status(500).send("OAuth failed");
  }
});

//logout
app.post("/v1/logout", (req, res) => {
  res.clearCookie("access_token", {
    httpOnly: true,
    secure: true,
    sameSite: "none",
  });
  return res.status(200).json({ message: "Logged out successfully" });
});

//profile
app.post("/v1/profiles", verifyJwt, async (req, res) => {
  try {
    const githubUsername = req.user.login;
    const access_token = req.user.access_token;
    const userData = await axios.get(
      `https://api.github.com/users/${githubUsername}`,
      {
        headers: {
          Authorization: `Bearer ${access_token}`,
          Accept: "application/vnd.github+json",
        },
      }
    );

    const { avatar_url, bio } = userData.data;

    const social_response = await axios.get(
      "https://api.github.com/user/social_accounts",
      {
        headers: {
          Authorization: `Bearer ${access_token}`,
          Accept: "application/vnd.github+json",
        },
      }
    );

    const linkedinUrl =
      social_response.data.find((data) => data.provider === "linkedin")?.url ||
      null;

    // Fetch GitHub repos
    const githubReposResponse = await axios.get(
      `https://api.github.com/users/${githubUsername}/repos`,
      {
        headers: { Accept: "application/vnd.github.v3+json" },
      }
    );

    const githubRepos = githubReposResponse.data;

    // Extract top 5 featured repositories based on stargazers count
    const featuredRepos = githubRepos
      .sort((a, b) => b.stargazers_count - a.stargazers_count)
      .slice(0, 5)
      .map((repo) => ({
        repoUrl: repo.html_url,
        description: repo.description || "No description",
      })); // get only 5 Repo

    console.log(userData);
    console.log(linkedinUrl);

    const existingUser = await User.findOne({ githubUsername });
    if (existingUser) {
      return res.status(200).json({
        message: "Profile already exists",
        profile: existingUser,
      });
    }

    const newProfile = new User({
      githubUsername,
      avatarUrl: avatar_url,
      bio,
      linkedinUrl,
      featuredRepos,
    });

    const savedProfile = await newProfile.save();

    res
      .status(201)
      .json({ message: "Profile created successfully", profile: savedProfile });
  } catch (error) {
    res.status(500).json("Internal server error");
  }
});

//profile details
app.get("/v1/profiles/:user_id/details", async (req, res) => {
  try {
    const profileDetails = await User.findById(req.params.user_id);
    if (!profileDetails) {
      return res.status(404).json({
        error: "NotFound",
        message: "Profile not found",
      });
    }
    res.status(200).json({ profile: profileDetails });
  } catch (error) {
    res.status(500).json("Internal server error");
  }
});

app.post("/v1/profiles/:user_id/tags", verifyJwt, async (req, res) => {
  try {
    const { tags } = req.body;
    const profile = await User.findById(req.params.user_id);
    if (!profile) {
      return res.status(404).json({
        error: "NotFound",
        message: "Profile not found",
      });
    }
    if (!Array.isArray(tags) || tags.length > 10) {
      return res.status(400).json({
        error: "BadRequest",
        message:
          "Invalid tags. Maximum 10 tags allowed with alphanumeric characters.",
      });
    }

    for (let i = 0; i < tags.length; i++) {
      if (
        typeof tags[i] !== "string" ||
        tags[i].length > 20 ||
        !/^[a-zA-Z0-9 ]+$/.test(tags[i])
      ) {
        return res.status(400).json({
          error: "BadRequest",
          message:
            "Invalid tags. Maximum 10 tags allowed with alphanumeric characters.",
        });
      }
    }

    const updatedProfile = await User.findByIdAndUpdate(
      req.params.user_id,
      { tags },
      { new: true }
    );

    res.status(200).json({
      message: "Tags added successfully.",
      tags: updatedProfile.tags,
    });
  } catch (error) {
    res.status(500).json("Internal server error");
  }
});

app.get("/v1/profiles/:user_id/tags", verifyJwt, async (req, res) => {
  try {
    const profile = await User.findById(req.params.user_id);
    if (!profile) {
      return res.status(404).json({
        error: "NotFound",
        message: "Profile not found",
      });
    }

    const tags = profile.tags;
    res.status(200).json({ tags });
  } catch (error) {
    res.status(500).json("Internal server error");
  }
});

app.post("/v1/profiles/:user_id", verifyJwt, async (req, res) => {
  try {
    const { bio, linkedinUrl, portfolioUrl, resumeUrl, tags } = req.body;
    const updateData = {};

    if (bio) {
      if (bio.length > 500) {
        return res.status(400).json({
          error: "BadRequest",
          message: "Invalid input data: Bio must be under 500 characters.",
        });
      }
      updateData.bio = bio;
    }

    if (linkedinUrl) {
      const urlPattern =
        /^(https?:\/\/)?([\w\-]+\.)+[\w\-]+(\/[\w\-._~:/?#[\]@!$&'()*+,;=]*)?$/;
      if (!urlPattern.test(linkedinUrl)) {
        return res.status(400).json({
          error: "BadRequest",
          message: "Invalid input data: LinkedIn URL is not valid.",
        });
      }
      updateData.linkedinUrl = linkedinUrl;
    }

    if (portfolioUrl) {
      const urlPattern =
        /^(https?:\/\/)?([\w\-]+\.)+[\w\-]+(\/[\w\-._~:/?#[\]@!$&'()*+,;=]*)?$/;
      if (!urlPattern.test(portfolioUrl)) {
        return res.status(400).json({
          error: "BadRequest",
          message: "Invalid input data: portfolio URL is not valid.",
        });
      }
      updateData.portfolioUrl = linkedinUrl;
    }

    if (resumeUrl) {
      updateData.resumeUrl = resumeUrl;
    }

    if (tags) {
      if (!Array.isArray(tags) || tags.length > 10) {
        return res.status(400).json({
          error: "BadRequest",
          message: "Invalid input data: Maximum 10 tags allowed.",
        });
      }

      for (let i = 0; i < tags.length; i++) {
        if (
          typeof tags[i] !== "string" ||
          tags[i].length > 20 ||
          !/^[a-zA-Z0-9 ]+$/.test(tags[i])
        ) {
          return res.status(400).json({
            error: "BadRequest",
            message:
              "Invalid input data: Tags must be alphanumeric and under 20 characters.",
          });
        }
      }

      updateData.tags = tags;
    }

    const updatedProfile = await User.findByIdAndUpdate(
      req.params.user_id,
      userData,
      { new: true }
    );

    if (!updatedProfile) {
      return res.status(404).json({
        error: "NotFound",
        message: "Profile not found",
      });
    }

    res.status(200).json({
      message: "Profile updated successfully",
      profile: updatedProfile,
    });
  } catch (error) {
    res.status(500).json("Internal server error");
  }
});

app.post(
  "/v1/profiles/:user_id/resume",
  verifyJwt,
  upload.single("file"),
  async (req, res) => {
    try {
      const user = await User.findById(req.params.user_id);

      if (!user) {
        return res.status(404).json({
          error: "NotFound",
          message: "User not found",
        });
      }

      const file = req.file;
      if (!file) {
        return res.status(400).json({
          error: "BadRequest",
          message: "No file uploaded",
        });
      }

      if (file.mimetype !== "application/pdf") {
        return res.status(400).json({
          error: "BadRequest",
          message: "Invalid file type. Only PDFs are allowed.",
        });
      }

      if (file.size > 2 * 1024 * 1024) {
        return res.status(400).json({
          error: "BadRequest",
          message: "File size exceeds 2MB limit.",
        });
      }

      const result = await cloudinary.uploader.upload(file.path, {
        folder: "uploads",
      });

      user.resumeUrl = result.secure_url;
      await user.save();

      res.status(200).json({
        message: "Resume uploaded successfully",
        resumeUrl: result.secure_url,
      });
    } catch (error) {
      res.status(500).json("Internal server error");
    }
  }
);

app.get("/v1/profiles/:user_id/resume", async (req, res) => {
  try {
    const user = await User.findById(req.params.user_id);

    if (!user) {
      return res.status(404).json({
        error: "NotFound",
        message: "User not found",
      });
    }

    if (!user.resumeUrl) {
      return res.status(404).json({
        error: "NotFound",
        message: "Resume not found",
      });
    }

    res.status(200).json({ resumeUrl: user.resumeUrl });
  } catch (error) {
    res.status(500).json("Internal server error");
  }
});

app.post("/v1/profiles/:user_id/slug", verifyJwt, async (req, res) => {
  try {
    const { customSlug } = req.body;

    const slugRegex = /^[a-zA-Z0-9-]+$/;
    if (!customSlug || !slugRegex.test(customSlug)) {
      return res.status(400).json({
        error: "BadRequest",
        message: "Invalid slug format",
      });
    }

    const existingUser = await User.findOne({ customSlug });
    if (existingUser) {
      return res.status(409).json({
        error: "Conflict",
        message: "Slug already exists",
      });
    }

    const user = await User.findByIdAndUpdate(
      req.params.user_id,
      { customSlug },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({
        error: "NotFound",
        message: "User not found",
      });
    }

    res.status(200).json({
      message: "Custom slug updated successfully",
      profile: user,
    });
  } catch (error) {
    res.status(500).json("Internal server error");
  }
});

app.get("/v1/profiles/:user_id/slug", verifyJwt, async (req, res) => {
  try {
    const user = await User.findById(req.params.user_id);

    if (!user) {
      return res.status(404).json({
        error: "NotFound",
        message: "User not found",
      });
    }

    if (!user.customSlug) {
      return res.status(404).json({
        error: "NotFound",
        message: "custom Slug not found",
      });
    }
    req.status(200).json({ customSlug: user.customSlug });
  } catch (error) {
    res.status(500).json("Internal server error");
  }
});

app.post("/v1/profiles/:user_id/featured", verifyJwt, async (req, res) => {
  try {
    const { featuredRepos } = req.body;

    if (!Array.isArray(featuredRepos) || featuredRepos.length > 5) {
      return res.status(400).json({
        error: "BadRequest",
        message: "You can only feature up to 5 repositories",
      });
    }

    const githubRepoRegex =
      /^https:\/\/github\.com\/[a-zA-Z0-9_-]+\/[a-zA-Z0-9_-]+$/;
    for (let i = 0; i < featuredRepos.length; i++) {
      let repo = featuredRepos[i];
      if (
        !repo.repoUrl ||
        !githubRepoRegex.test(repo.repoUrl) ||
        typeof repo.description !== "string"
      ) {
        return res.status(400).json({
          error: "BadRequest",
          message: "Invalid repository URL or description",
        });
      }
    }

    const user = await User.findById(req.params.user_id);

    if (!user) {
      return res.status(404).json({
        error: "NotFound",
        message: "User not found",
      });
    }

    user.featuredRepos = featuredRepos;
    await user.save();

    res.status(200).json({
      message: "Added the repo in featured",
    });
  } catch (error) {
    res.status(500).json("Internal server error");
  }
});

app.get("/v1/profiles/:user_id/featured", verifyJwt, async (req, res) => {
  try {
    const user = await User.findById(req.params.user_id);

    if (!user) {
      return res.status(404).json({
        error: "NotFound",
        message: "User not found",
      });
    }

    res
      .status(200)
      .json({ user: user.githubUsername, featuredRepos: user.featuredRepos });
  } catch (error) {
    res.status(500).json("Internal server error");
  }
});

app.get("/v1/profiles/search", async (req, res) => {
  try {
    const { tags } = req.query;

    if (!tags) {
      return res.status(400).json({
        error: "BadRequest",
        message: "Tags query parameter is required",
      });
    }

    const tagArray = tags.split(",").map((tag) => tag.trim().toLowerCase());
    const users = await User.find({
      tags: { $in: tagArray },
    });

    res.status(200).json(users);
  } catch (error) {
    res.status(500).json("Internal server error");
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on ${PORT}`);
});
