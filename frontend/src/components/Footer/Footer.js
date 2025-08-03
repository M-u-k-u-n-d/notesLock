import React from "react";
import { Link } from "react-router-dom";
import {
  FaGithub ,
  FaTwitter,
  FaLinkedinIn,
  FaLaptopCode,
} from "react-icons/fa";

const Footer = () => {
  const currentYear = new Date().getFullYear();
  return (
    <footer className="bg-headerColor py-6 lg:py-2  min-h-28 z-50  relative">
      <div className="xl:px-10 sm:px-6 px-4  min-h-28  flex lg:flex-row flex-col  lg:gap-0 gap-5  justify-between items-center ">
        <ul className="flex flex-1  md:gap-6 gap-4   text-white flex-row items-center ">
          <li>
            <Link to="/">
              <span className="hover:underline">Services</span>
            </Link>
          </li>
          <li>
            <Link to="/">
              <span className="hover:underline">Privacy Policy</span>
            </Link>
          </li>
        </ul>

        <div className="flex-1  flex flex-row gap-6 lg:justify-end justify-start items-center">
          <Link
            className="text-white border h-10 w-10 flex justify-center items-center border-white rounded-full p-2 hover:bg-blue-600 transition-colors duration-300"
            to="https://github.com/M-u-k-u-n-d"
            target="_blank"
          >
            <FaGithub  width={20} height={20} />
          </Link>{" "}
          <Link
            className="text-white border h-10 w-10 flex justify-center items-center border-white rounded-full p-2 hover:bg-blue-600 transition-colors duration-300"
            to="https://www.linkedin.com/in/mukund-tiwari-06b433219/"
            target="_blank"
          >
            <FaLinkedinIn width={20} height={20} />
          </Link>{" "}
          <Link
            className="text-white border h-10 w-10 flex justify-center items-center border-white rounded-full p-2 hover:bg-blue-600 transition-colors duration-300"
            to="https://x.com/itsMukundTiwari"
            target="_blank"
          >
            <FaTwitter width={20} height={20} />
          </Link>{" "}
          <Link
            className="text-white border h-10 w-10 flex justify-center items-center border-white rounded-full p-2 hover:bg-blue-600 transition-colors duration-300"
            to="https://leetcode.com/u/Mukund_Tiwari/"
            target="_blank"
          >
            <FaLaptopCode width={20} height={20} />
          </Link>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
