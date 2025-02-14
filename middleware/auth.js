import jwt from "jsonwebtoken";

const checkUserAuth = (req, res, next) => {
  try {
    const access_token = req.headers.authorization.split("Bearer ")[1];
    // console.log(access_token)
    if (!access_token) {
      return res.status(401).json({ message: "Unauthorized User, No Token" });
    }

    // Verify Token
    const validity = jwt.verify(access_token, process.env.JWT_SECRET_KEY);
    // console.log(validity)
    if (validity) {
      const { userID } = validity;
      const user = {
        userID,
      };
      req.user = user; // Attach user to request
      return next(); // Proceed to the next middleware
    } else {
      return res.status(400).json({ message: "Invalid Token" });
    }
  } catch (error) {
    return res
      .status(401)
      .json({ message: "Unauthorized: Invalid or Expired Token" });
  }
};

export default checkUserAuth;
