import type { Metadata } from "next";
import "./globals.css";
import ClinetLayout from "./ClientLayout";
import localFont from "next/font/local";
import '@smastrom/react-rating/style.css'

export const metadata: Metadata = {
  title: "Create Next App",
  description: "Generated by create next app",
};

const pretendard = localFont({
  src: "./../../node_modules/pretendard/dist/web/variable/woff2/PretendardVariable.woff2",
  display: "swap",
  weight: "45 920",
  variable: "--font-pretendard",
});

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <ClinetLayout
      fontVariable={pretendard.variable}
      fontClassName={pretendard.className}
    >
      {children}
    </ClinetLayout>
  );
}
