import { type NextPage } from "next";
import Head from "next/head";
import Link from "next/link";
import { signIn, signOut, useSession } from "next-auth/react";
import { useForm, SubmitHandler } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";

import { trpc } from "../utils/trpc";

interface IUserRegisterFormInputs {
  email: string;
  password: string;
}

const userRegisterSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

const Register: NextPage = () => {
  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<IUserRegisterFormInputs>({
    resolver: zodResolver(userRegisterSchema),
  });

  const userRegister = trpc.user.registerUser.useMutation();

  const handleLogin = handleSubmit(async (data) => {
    userRegister.mutate({
      email: data.email,
      password: data.password,
    });
  });

  return (
    <>
      <Head>
        <title>Register</title>
        <meta name="description" content="Generated by create-t3-app" />
        <link rel="icon" href="/favicon.ico" />
      </Head>
      <main className="flex min-h-screen flex-col items-center justify-center bg-gradient-to-b from-[#2e026d] to-[#15162c]">
        <div className="container flex flex-col items-center justify-center gap-12 px-4 py-16 ">
          <h1 className="text-5xl font-extrabold tracking-tight text-white sm:text-[5rem]">
            Sign <span className="text-[hsl(280,100%,70%)]">in</span>
          </h1>
          <form onSubmit={handleLogin} className="flex flex-col gap-4">
            <input {...register("email")} type="email" className="px-4 py-2" />
            <p>{errors.email?.message}</p>
            <input
              {...register("password")}
              type="password"
              className="px-4 py-2"
            />
            <p>{errors.email?.message}</p>
            <button type="submit" className="bg-white px-4 py-2">
              Register
            </button>
          </form>
        </div>
      </main>
    </>
  );
};

export default Register;