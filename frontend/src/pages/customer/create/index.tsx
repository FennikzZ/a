import {
  Space,
  Button,
  Col,
  Row,
  Divider,
  Form,
  Input,
  Card,
  message,
  DatePicker,
  InputNumber,
  Select,
  Upload,
} from "antd";
import { PlusOutlined } from "@ant-design/icons";
import { useState } from "react";
import ImgCrop from "antd-img-crop";
import { UsersInterface } from "../../../interfaces/IUser";
import { CreateUser } from "../../../services/https";
import { useNavigate, Link } from "react-router-dom";

function CustomerCreate() {
  const navigate = useNavigate();
  const [messageApi, contextHolder] = message.useMessage();
  const [fileList, setFileList] = useState([]);

  const onChange = ({ fileList: newFileList }) => setFileList(newFileList);

  const onPreview = async (file) => {
    let src = file.url;
    if (!src) {
      src = await new Promise((resolve) => {
        const reader = new FileReader();
        reader.readAsDataURL(file.originFileObj);
        reader.onload = () => resolve(reader.result);
      });
    }
    const imgWindow = window.open(src);
    imgWindow.document.write(`<img src="${src}" />`);
  };

  const onFinish = async (values: UsersInterface) => {
    // Set the profile image from the uploaded file
    if (fileList.length > 0) {
      values.Profile = fileList[0].thumbUrl;
    }
    let res = await CreateUser(values);

    if (res.status === 201) {
      messageApi.open({
        type: "success",
        content: res.data.message,
      });
      setTimeout(function () {
        navigate("/customer");
      }, 2000);
    } else {
      messageApi.open({
        type: "error",
        content: res.data.error,
      });
    }
  };

  return (
    <div>
      {contextHolder}
      <Card>
        <h2>เพิ่มข้อมูล ผู้ดูแลระบบ</h2>
        <Divider />

        <Form name="basic" layout="vertical" onFinish={onFinish} autoComplete="off">
          <Row gutter={[16, 0]}>
            {/* First Name */}
            <Col xs={24} sm={24} md={24} lg={24} xl={12}>
              <Form.Item
                label="ชื่อจริง"
                name="first_name"
                rules={[
                  {
                    required: true,
                    message: "กรุณากรอกชื่อจริง!",
                  },
                ]}
              >
                <Input />
              </Form.Item>
            </Col>

            {/* Last Name */}
            <Col xs={24} sm={24} md={24} lg={24} xl={12}>
              <Form.Item
                label="นามสกุล"
                name="last_name"
                rules={[
                  {
                    required: true,
                    message: "กรุณากรอกนามสกุล!",
                  },
                ]}
              >
                <Input />
              </Form.Item>
            </Col>

            {/* Email */}
            <Col xs={24} sm={24} md={24} lg={24} xl={12}>
              <Form.Item
                label="อีเมล"
                name="email"
                rules={[
                  {
                    type: "email",
                    message: "รูปแบบอีเมลไม่ถูกต้อง!",
                  },
                  {
                    required: true,
                    message: "กรุณากรอกอีเมล!",
                  },
                ]}
              >
                <Input />
              </Form.Item>
            </Col>

            {/* Password */}
            <Col xs={24} sm={24} md={24} lg={24} xl={12}>
              <Form.Item
                label="รหัสผ่าน"
                name="password"
                rules={[
                  {
                    required: true,
                    message: "กรุณากรอกรหัสผ่าน!",
                  },
                ]}
              >
                <Input.Password />
              </Form.Item>
            </Col>

            {/* Birthday */}
            <Col xs={24} sm={24} md={24} lg={24} xl={12}>
              <Form.Item
                label="วัน/เดือน/ปี เกิด"
                name="birthday"
                rules={[
                  {
                    required: true,
                    message: "กรุณาเลือกวัน/เดือน/ปี เกิด!",
                  },
                ]}
              >
                <DatePicker style={{ width: "100%" }} />
              </Form.Item>
            </Col>

            {/* Age */}
            <Col xs={24} sm={24} md={24} lg={24} xl={12}>
              <Form.Item
                label="อายุ"
                name="age"
                rules={[
                  {
                    required: true,
                    message: "กรุณากรอกอายุ!",
                  },
                ]}
              >
                <InputNumber
                  min={0}
                  max={99}
                  defaultValue={0}
                  style={{ width: "100%" }}
                />
              </Form.Item>
            </Col>

            {/* Gender */}
            <Col xs={24} sm={24} md={24} lg={24} xl={12}>
              <Form.Item
                label="เพศ"
                name="gender_id"
                rules={[
                  {
                    required: true,
                    message: "กรุณาเลือกเพศ!",
                  },
                ]}
              >
                <Select
                  defaultValue=""
                  style={{ width: "100%" }}
                  options={[
                    { value: "", label: "กรุณาเลือกเพศ", disabled: true },
                    { value: 1, label: "Male" },
                    { value: 2, label: "Female" },
                  ]}
                />
              </Form.Item>
            </Col>

            {/* Address */}
            <Col xs={24} sm={24} md={24} lg={24} xl={12}>
              <Form.Item
                label="ที่อยู่"
                name="address"
                rules={[
                  {
                    required: true,
                    message: "กรุณากรอกที่อยู่!",
                  },
                ]}
              >
                <Input />
              </Form.Item>
            </Col>

            {/* Category */}
            <Col xs={24} sm={24} md={24} lg={24} xl={12}>
              <Form.Item
                label="หมวดหมู่"
                name="category"
                rules={[
                  {
                    required: true,
                    message: "กรุณากรอกหมวดหมู่!",
                  },
                ]}
              >
                <Input />
              </Form.Item>
            </Col>

            {/* Wages */}
            <Col xs={24} sm={24} md={24} lg={24} xl={12}>
              <Form.Item
                label="ค่าจ้าง"
                name="Wages"
                rules={[
                  {
                    required: true,
                    message: "กรุณากรอกค่าจ้าง!",
                  },
                ]}
              >
                <InputNumber
                  min={0}
                  max={999999}
                  defaultValue={0}
                  style={{ width: "100%" }}
                />
              </Form.Item>
            </Col>

            {/* Contact */}
            <Col xs={24} sm={24} md={24} lg={24} xl={12}>
              <Form.Item
                label="เบอร์โทรศัพท์"
                name="Contact"
                rules={[
                  {
                    required: true,
                    message: "กรุณากรอกเบอร์โทรศัพท์!",
                  },
                ]}
              >
                <Input />
              </Form.Item>
            </Col>

            {/* Profile Picture Upload */}
            <Col xs={24} sm={24} md={24} lg={24} xl={12}>
              <Form.Item label="รูปประจำตัว" name="Profile">
                <ImgCrop rotationSlider>
                  <Upload
                    listType="picture-card"
                    fileList={fileList}
                    onChange={onChange}
                    onPreview={onPreview}
                    beforeUpload={() => false} // Prevent immediate upload
                    maxCount={1}
                  >
                    {fileList.length < 1 && (
                      <div>
                        <PlusOutlined />
                        <div style={{ marginTop: 8 }}>อัพโหลด</div>
                      </div>
                    )}
                  </Upload>
                </ImgCrop>
              </Form.Item>
            </Col>
          </Row>

          <Row justify="end">
            <Col style={{ marginTop: "40px" }}>
              <Form.Item>
                <Space>
                  <Link to="/customer">
                    <Button htmlType="button" style={{ marginRight: "10px" }}>
                      ยกเลิก
                    </Button>
                  </Link>

                  <Button type="primary" htmlType="submit" icon={<PlusOutlined />}>
                    ยืนยัน
                  </Button>
                </Space>
              </Form.Item>
            </Col>
          </Row>
        </Form>
      </Card>
    </div>
  );
}

export default CustomerCreate;
