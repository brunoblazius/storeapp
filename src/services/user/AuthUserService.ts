import { sign } from "jsonwebtoken";
import prismaClient from "../../prisma"
import { compare } from "bcryptjs";

interface AuthRequest {
    email: string;
    password: string;
}

class AuthUserService {
    async execute( {email, password}: AuthRequest ) {
        const user = await prismaClient.user.findFirst({
            where: {
                email: email
            }
        })

        if(!user) {
            throw new Error("User/Pass incorrect!");
        }

        const passwordMath = await compare(password, user.password)

        if (!passwordMath) {
            throw new Error("User/Pass incorrect!");
        }

        const token = sign(
            {
                name: user.name,
                email: user.email
            },
            process.env.SECRET_JWT,
            {
                subject: user.id,
                expiresIn: '30d'
            }
        );

        return { id: user.id, name: user.name, email: user.email, token: token }
    }
}

export { AuthUserService }