import NextAuth, { type NextAuthOptions } from "next-auth";
import DiscordProvider from "next-auth/providers/discord";
import CredentialsProvider from "next-auth/providers/credentials";
// Prisma adapter for NextAuth, optional and can be removed
import { PrismaAdapter } from "@next-auth/prisma-adapter";

import { env } from "../../../env/server.mjs";
import { prisma } from "../../../server/db/client";

import * as argon2 from "argon2";
import { User } from "@prisma/client";

export const authOptions: NextAuthOptions = {
  // Include user.id on session
  callbacks: {
    session({ session, user }) {
      if (session.user) {
        session.user.id = user.id;
      }
      return session;
    },
  },
  // Configure one or more authentication providers
  adapter: PrismaAdapter(prisma),
  providers: [
    DiscordProvider({
      clientId: env.DISCORD_CLIENT_ID,
      clientSecret: env.DISCORD_CLIENT_SECRET,
    }),
    CredentialsProvider({
      name: "email",
      credentials: {
        email: { label: "Email", type: "email", placeholder: "john@doe.com" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials, req) {
        const user: User | null = await prisma.user.findFirst({
          where: {
            email: credentials?.email,
          },
        });

        if (!user) return null;

        console.log(credentials);
        const isPasswordCorrect = await argon2.verify(
          user.password,
          credentials?.password!
        );

        console.log(isPasswordCorrect);
        if (!isPasswordCorrect) return null;

        return user;
      },
    }),
  ],
};

export default NextAuth(authOptions);
