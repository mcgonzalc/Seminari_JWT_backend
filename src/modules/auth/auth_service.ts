import { encrypt, verified } from "../../utils/bcrypt.handle.js";
import { generateToken } from "../../utils/jwt.handle.js";
import User, { IUser } from "../users/user_models.js";
import { Auth } from "./auth_model.js";
import jwt from 'jsonwebtoken';
import axios from 'axios';

// Función para generar el Access Token
const generateAccessToken = (user: any, additionalData: any = {}) => {
    const payload = {
        email: user.email,
        name: user.name,
        age: user.age,
        role: "Admin",
        ...additionalData, //Permite agregar más data
    };
    return jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET!, { expiresIn: '15m' });
};

// Función para generar el Refresh Token
const generateRefreshToken = (user: any, additionalData: any = {}) => {
    const payload = {
        email: user.email,
        name: user.name,
        age: user.age,
        role: "Admin",
    };
    return jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET!, { expiresIn: "7d" });
};

const registerNewUser = async ({ email, password, name, age }: IUser) => {
    const checkIs = await User.findOne({ email });
    if(checkIs) return "ALREADY_USER";

    const passHash = await encrypt(password);

    const registerNewUser = await User.create({
        email,
        password: passHash,
        name,
        age
    });

    return registerNewUser;
};

const loginUser = async ({ email, password }: Auth) => {
    const user = await User.findOne({ email });

    if (!user) return "NOT_FOUND_USER";

    const passwordHash = user.password; //El encriptado que viene de la bbdd
    const isCorrect = await verified(password, passwordHash);

    if (!isCorrect) return "INCORRECT_PASSWORD";

    // Generar access token y refresh token
    const accessToken = generateAccessToken(user, { /* Data extra para el access token */ });
    const refreshToken = generateRefreshToken(user, { /* Data extra para el refresh token */ });

    const data = {
        accessToken,
        refreshToken,
        user
    };

    return data;
};

const googleAuth = async (code: string) => {
    try {
        console.log("Client ID:", process.env.GOOGLE_CLIENT_ID);
        console.log("Client Secret:", process.env.GOOGLE_CLIENT_SECRET);
        console.log("Redirect URI:", process.env.GOOGLE_OAUTH_REDIRECT_URL);

        if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET || !process.env.GOOGLE_OAUTH_REDIRECT_URL) {
            throw new Error("Variables de entorno faltantes");
        }

        interface TokenResponse {
            access_token: string;
            expires_in: number;
            scope: string;
            token_type: string;
            id_token?: string;
        }

        // Obtener el token de acceso desde Google
        const tokenResponse = await axios.post<TokenResponse>('https://oauth2.googleapis.com/token', {
            code,
            client_id: process.env.GOOGLE_CLIENT_ID,
            client_secret: process.env.GOOGLE_CLIENT_SECRET,
            redirect_uri: process.env.GOOGLE_OAUTH_REDIRECT_URL,
            grant_type: 'authorization_code'
        });

        const access_token = tokenResponse.data.access_token;
        console.log("Access Token:", access_token);

        // Obtener el perfil del usuario desde Google
        const profileResponse = await axios.get('https://www.googleapis.com/oauth2/v1/userinfo', {
            params: { access_token },
            headers: { Accept: 'application/json' },
        });

        const profile = profileResponse.data as { name: string; email: string; id: string };

        // Validar que el correo electrónico existe
        if (!profile.email) {
            throw new Error("El perfil de Google no contiene un correo electrónico válido");
        }

        console.log("Access profile:", profile);

        // Buscar o crear el usuario en la base de datos
        let user = await User.findOne({
            $or: [{ email: profile.email }, { googleId: profile.id }]
        });

        if (!user) {
            const randomPassword = Math.random().toString(36).slice(-8);
            const passHash = await encrypt(randomPassword);

            user = await User.create({
                name: profile.name,
                email: profile.email, // Asegúrate de que este campo tenga un valor válido
                googleId: profile.id,
                password: passHash,
            });
        }

        // Generar access token y refresh token
        const accessToken = generateAccessToken(user, { /* Data extra para el access token */ });
        const refreshToken = generateRefreshToken(user, { /* Data extra para el refresh token */ });

        return { accessToken, refreshToken, user };
    } catch (error) {
        if (error instanceof Error) {
            console.error('Google Auth Error:', error.message); // Ahora es seguro acceder a error.message
        } else {
            console.error('Google Auth Error desconocido:', error); // Manejo genérico para errores no esperados
        }
        
        throw new Error('Error en autenticación con Google');
    }
};

export { registerNewUser, loginUser, googleAuth, generateAccessToken, generateRefreshToken };