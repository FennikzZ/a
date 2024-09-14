import { UsersInterface } from "../../interfaces/IUser";
import { SignInInterface } from "../../interfaces/SignIn";
import { WorkInterface } from "../../interfaces/Work";
import { ResumeInterface } from "../../interfaces/IResume";
import axios from "axios";

const apiUrl = "http://localhost:8000";
const Authorization = localStorage.getItem("token") || '';
const Bearer = localStorage.getItem("token_type") || '';

const requestOptions = {
  headers: {
    "Content-Type": "application/json",
    Authorization: `${Bearer} ${Authorization}`,
  },
};

async function SignIn(data: SignInInterface) {
  return await axios
    .post(`${apiUrl}/signin`, data, requestOptions)
    .then((res) => {
      // เก็บ resume_id ใน localStorage
      localStorage.setItem("resume_id", res.data.resume_id);
      return res;
    })
    .catch((e) => e.response);
}

async function GetUsers() {
  return await axios
    .get(`${apiUrl}/users`, requestOptions)
    .then((res) => res)
    .catch((e) => e.response);
}

async function GetWork() {
  return await axios
    .get(`${apiUrl}/works`, requestOptions)
    .then((res) => res)
    .catch((e) => e.response);
}

async function GetPostwork() {
  return await axios
    .get(`${apiUrl}/postworks`, requestOptions)
    .then((res) => res)
    .catch((e) => e.response);
}

async function GetUsersById(id: string) {
  return await axios
    .get(`${apiUrl}/user/${id}`, requestOptions)
    .then((res) => res)
    .catch((e) => e.response);
}

async function GetWorkById(id: string) {
  return await axios
    .get(`${apiUrl}/work/${id}`, requestOptions)
    .then((res) => res)
    .catch((e) => e.response);
}

async function GetPostworkById(id: string) {
  return await axios
    .get(`${apiUrl}/postwork/${id}`, requestOptions)
    .then((res) => res)
    .catch((e) => e.response);
}

async function UpdateUsersById(id: string, data: UsersInterface) {
  return await axios
    .put(`${apiUrl}/user/${id}`, data, requestOptions)
    .then((res) => res)
    .catch((e) => e.response);
}

async function UpdateWorkById(id: string, data: WorkInterface) {
  return await axios
    .put(`${apiUrl}/work/${id}`, data, requestOptions)
    .then((res) => res)
    .catch((e) => e.response);
}

async function UpdateResumeById(id: string, data: ResumeInterface) {
  return await axios
    .put(`${apiUrl}/resumes/${id}`, data, requestOptions)
    .then((res) => res)
    .catch((e) => e.response);
}

async function DeleteUsersById(id: string) {
  return await axios
    .delete(`${apiUrl}/user/${id}`, requestOptions)
    .then((res) => res)
    .catch((e) => e.response);
}

async function DeleteWorkById(id: string) {
  return await axios
    .delete(`${apiUrl}/work/${id}`, requestOptions)
    .then((res) => res)
    .catch((e) => e.response);
}

async function DeletePostworkById(id: string) {
  return await axios
    .delete(`${apiUrl}/postwork/${id}`, requestOptions)
    .then((res) => res)
    .catch((e) => e.response);
}

async function DeleteResumeById(id: string) {
  return await axios
    .delete(`${apiUrl}/resumes/${id}`, requestOptions)
    .then((res) => res)
    .catch((e) => e.response);
}

async function CreateUser(data: UsersInterface) {
  return await axios
    .post(`${apiUrl}/signup`, data, requestOptions)
    .then((res) => res)
    .catch((e) => e.response);
}

async function CreateWork(data: WorkInterface) {
  return await axios
    .post(`${apiUrl}/works`, data, requestOptions)
    .then((res) => res)
    .catch((e) => e.response);
}

async function CreateResume(data: ResumeInterface) {
  return await axios
    .post(`${apiUrl}/resumes`, data, requestOptions)
    .then((res) => res)
    .catch((e) => e.response);
}

async function GetResume() {
  return await axios
    .get(`${apiUrl}/resumes`, requestOptions)
    .then((res) => res)
    .catch((e) => e.response);
}

async function GetResumeById(resume_id: string) {
  const resumeId = localStorage.getItem("resume_id");
  if (!resumeId) {
    throw new Error("No resume_id found in local storage");
  }

  return await axios
    .get(`${apiUrl}/resumes/${resumeId}`, requestOptions)
    .then((res) => res)
    .catch((e) => e.response);
}


// ตัวอย่างฟังก์ชัน GetUserProfile
export const GetUserProfile = async () => {
  try {
    const response = await fetch('/api/user/profile'); // ตรวจสอบ URL และวิธีการเรียกใช้
    if (!response.ok) {
      throw new Error('Network response was not ok.');
    }
    return await response.json();
  } catch (error) {
    console.error('Error fetching user profile:', error);
    throw error; // โยนข้อผิดพลาดให้กับ caller
  }
};
;

export {
  SignIn,
  GetUsers,
  GetUsersById,
  UpdateUsersById,
  DeleteUsersById,
  CreateUser,
  GetWork,
  GetWorkById,
  UpdateWorkById,
  DeleteWorkById,
  CreateWork,
  GetPostwork,
  GetPostworkById,
  DeletePostworkById,
  // Resume
  CreateResume,
  GetResume,
  UpdateResumeById, // Added this line
  DeleteResumeById,
  GetResumeById,
};