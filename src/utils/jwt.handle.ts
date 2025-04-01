import pkg from "jsonwebtoken";
import jwt from 'jsonwebtoken';
const { sign, verify } = pkg;   //Importamos las funciones sign y verify de la librería jsonwebtoken
const JWT_SECRET = process.env.ACCESS_TOKEN_SECRET || "jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj";

const generateToken = (email: string, additionalData: any = {}) => {
    const payload = {
        email: email,
        ...additionalData // Aquí se incluyen los datos adicionales
    };
    return jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET || "jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj", {
        expiresIn: "2h",
    });
};

const verifyToken = (jwt: string) => {
    const isOk = verify(jwt, JWT_SECRET);
    return isOk;

};

export { generateToken, verifyToken };