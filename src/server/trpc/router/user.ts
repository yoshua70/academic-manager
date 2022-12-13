import { z } from "zod";
import { router, publicProcedure } from "../trpc";
import * as argon2 from "argon2";
import { TRPCError } from "@trpc/server";

export const userRouter = router({
  registerUser: publicProcedure
    .input(z.object({ email: z.string().email(), password: z.string().min(8) }))
    .mutation(async ({ ctx, input }) => {
      return ctx.prisma.user.create({
        data: {
          email: input.email,
          password: await argon2.hash(input.password),
        },
      });
    }),
  signInUser: publicProcedure
    .input(z.object({ email: z.string().email(), password: z.string().min(8) }))
    .query(async ({ ctx, input }) => {
      const user = await ctx.prisma.user.findFirst({
        where: {
          email: input.email,
        },
      });

      if (!user)
        throw new TRPCError({
          message: "User is not registered",
          code: "NOT_FOUND",
        });

      const isPasswordCorrect = await argon2.verify(
        user.password,
        input.password
      );

      if (!isPasswordCorrect)
        throw new TRPCError({
          message: "Password is incorrect",
          code: "UNAUTHORIZED",
        });

      return user;
    }),
});
