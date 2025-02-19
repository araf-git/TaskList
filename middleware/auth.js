import jwt from "jsonwebtoken";

const checkUserAuth = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized User, No Token" });
    }

    const access_token = authHeader.split("Bearer ")[1];

    // Verify Token
    const validity = jwt.verify(access_token, process.env.JWT_SECRET_KEY);
    if (validity) {
      req.user = { userID: validity.userID }; // Attach user to request
      return next(); // Proceed to the next middleware
    }

    return res.status(400).json({ message: "Invalid Token" });
  } catch (error) {
    return res
      .status(401)
      .json({ message: "Unauthorized: Invalid or Expired Token" });
  }
};

export default checkUserAuth;
