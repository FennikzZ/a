import React, { useState } from "react";
import { Routes, Route, Link } from "react-router-dom";
import "../../App.css";
import {
  UserOutlined,
  PlusOutlined,
  HomeOutlined,
} from "@ant-design/icons";
import { Breadcrumb, Layout, Button, message, theme } from "antd";
import logo from "../../assets/logo.png";
import videoBg from "../../assets/back.mp4"; // Background video
import Dashboard from "../../pages/dashboard";
import Try from "../../pages/Try";
import Post from "../../pages/Post";
import Customer from "../../pages/customer";
import CustomerCreate from "../../pages/customer/create";
import CustomerEdit from "../../pages/customer/edit";
import WorkCreate from "../../pages/Post/create";
import WorkEdit from "../../pages/Post/edit";
import Work from "../../pages/Post";
import Postwork from "../../pages/postwork";
//resume
import Resume from "../../pages/resume";
import ResumeCreate from "../../pages/resume/create";
import ResumeEdit from "../../pages/resume/edit";
import ResumeView from "../../pages/resume/view";

const { Header, Content } = Layout;

const FullLayout: React.FC = () => {
  const [messageApi, contextHolder] = message.useMessage();

  const {
    token: { colorBgContainer },
  } = theme.useToken();

  const setCurrentPage = (val: string) => {
    localStorage.setItem("page", val);
    if (val === "dashboard") {
      window.location.reload(); // Refresh the page when clicking "Home"
    }
  };

  const Logout = () => {
    localStorage.clear();
    messageApi.success("Logout successful");
    setTimeout(() => {
      location.href = "/";
    }, 2000);
  };

  return (
    <Layout style={{ minHeight: "100vh", position: 'relative' }}>
      {contextHolder}

      {/* Background video */}
      <div style={{
        position: 'absolute',
        top: 0,
        left: 0,
        width: '100%',
        height: '100%',
        zIndex: 0,
        overflow: 'hidden'
      }}>
        <video
          autoPlay
          loop
          muted
          style={{
            position: "absolute",
            top: 0,
            left: 0,
            width: "100%",
            height: "100%",
            objectFit: "cover",
            zIndex: -1, // Ensure the video stays behind the content
            filter: "brightness(0.4)" // Adjust brightness for better content visibility
          }}
        >
          <source src={videoBg} type="video/mp4" />
        </video>
      </div>

      <Layout style={{ position: 'relative', zIndex: 1 }}>
        <Header style={{ background: '#06579b', padding: 0, display: 'flex', justifyContent: 'space-between', alignItems: 'center', position: 'relative', zIndex: 2 }}>
          <div style={{ display: 'flex', alignItems: 'center' }}>
            <img src={logo} alt="Logo" style={{ width: 50, margin: '0 10px' }} />
            <h1 style={{ color: 'white' }}> Capylance</h1>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', marginRight: '20px' }}>
            <Button 
              type="text" 
              style={{ color: 'white', margin: '0 10px' }} 
              onClick={() => setCurrentPage("dashboard")}
            >
              <Link to="/">
                <HomeOutlined style={{ color: 'white' }} />
                <span style={{ color: 'white' }}> หน้าหลัก</span>
              </Link>
            </Button>
            <Button 
              type="text" 
              style={{ color: 'white', margin: '0 10px' }} 
              onClick={() => setCurrentPage("Try")}
            >
              <Link to="/t">
                <PlusOutlined style={{ color: 'white' }} />
                <span style={{ color: 'white' }}> โพสงาน</span>
              </Link>
            </Button>
            <Button 
              type="text" 
              style={{ color: 'white', margin: '0 10px' }} 
              onClick={() => setCurrentPage("customer")}
            >
              <Link to="/customer">
                <UserOutlined style={{ color: 'white' }} />
                <span style={{ color: 'white' }}> Customer</span>
              </Link>
            </Button>
            <Button 
              type="text" 
              style={{ color: 'white', margin: '0 10px' }} 
              onClick={() => setCurrentPage("resume")}
            >
              <Link to="/resume">
                <UserOutlined style={{ color: 'white' }} />
                <span style={{ color: 'white' }}> Resume</span>
              </Link>
            </Button>
            <Button 
              type="primary" 
              onClick={Logout} 
              style={{ marginLeft: '20px' }}
            >
              ออกจากระบบ
            </Button>
          </div>
        </Header>

        <Content style={{ margin: "0", padding: '16px', background: "#FFFFFF", minHeight: 'calc(100vh - 80px - 64px)', position: 'relative', zIndex: 1 }}>
          <Breadcrumb style={{ margin: "16px 0" }} />
          <div style={{ padding: 24, minHeight: "100%", background: 'rgba(240, 242, 245, 0.8)' }}>
  <Routes>
    <Route path="/" element={<Dashboard />} />
    <Route path="/t" element={<Try />} />
    <Route path="/customer" element={<Customer />} />
    <Route path="/customer/create" element={<CustomerCreate />} />
    <Route path="/customer/edit/:id" element={<CustomerEdit />} />
    <Route path="/work" element={<Work />} />
    <Route path="/work/create" element={<WorkCreate />} />
    <Route path="/work/edit/:id" element={<WorkEdit />} />
    <Route path="/go" element={<Postwork />} />
    //resume
    <Route path="/resume" element={<Resume />} />
    <Route path="/resume/create" element={<ResumeCreate />} />
    <Route path="/resume/edit/:id" element={<ResumeEdit />} />
    <Route path="/resume/view/:id" element={<ResumeView />} />
  </Routes>
</div>
        </Content>
      </Layout>
    </Layout>
  );
};

export default FullLayout;
