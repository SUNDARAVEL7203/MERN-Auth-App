import jwt from "jsonwebtoken";

const userAuth = async (req, res, next) => {
    try {
        // Extract token from cookies
        const { token } = req.cookies;

        if (!token) {
            return res.status(401).json({ success: false, message: "Not Authorized. Login Again" });
        }

        // Verify token
        const tokenDecode = jwt.verify(token, process.env.JWT_SECRET);

        if (!tokenDecode || !tokenDecode.id) {
            return res.status(401).json({ success: false, message: "Invalid Token. Login Again" });
        }

        // Attach userId to request body
        req.body.userId = tokenDecode.id;

        next(); // Proceed to the next middleware
    } catch (error) {
        return res.status(401).json({ success: false, message: "Authentication Failed: " + error.message });
    }
};

export default userAuth;