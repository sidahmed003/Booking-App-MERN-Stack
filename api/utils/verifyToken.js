import jwt from "jsonwebtoken";
import { createError } from "../utils/verifyToken.js";

export const verifyToken = async (req,res,next) => {
    const token = req.cookies.access_token ;
    if (!token) {
        return next(createError(401, "You are not authenticated!"));
    }

    jwt.verify(token, process.env.JWT, (err, user));
}