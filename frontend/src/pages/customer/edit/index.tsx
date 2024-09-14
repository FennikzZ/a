import { useEffect, useState } from "react";
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
import { UsersInterface } from "../../../interfaces/IUser";
import { GetUsersById, UpdateUsersById } from "../../../services/https/index";
import { useNavigate, Link, useParams } from "react-router-dom";
import dayjs from "dayjs";
import ImgCrop from "antd-img-crop";

function CustomerEdit() {
  const navigate = useNavigate();
  const { id } = useParams<{ id: any }>();
  const [messageApi, contextHolder] = message.useMessage();
  const [form] = Form.useForm();
  const [fileList, setFileList] = useState([]);

  const getUserById = async (id: string) => {
    let res = await GetUsersById(id);
    if (res.status === 200) {
      form.setFieldsValue({
        first_name: res.data.first_name,
        last_name: res.data.last_name,
        email: res.data.email,
        birthday: dayjs(res.data.birthday),
        age: res.data.age,
        gender_id: res.data.gender?.ID,
        address: res.data.address,
        Category: res.data.Category,
        Wages: res.data.Wages,
        Contact: res.data.Contact,
      });
      if (res.data.Profile) {
        setFileList([
          {
            uid: '-1',
            name: 'image.png',
            status: 'done',
            url: res.data.Profile,
            thumbUrl: res.data.Profile,
          },
        ]);
      }
    } else {
      messageApi.open({
        type: "error",
        content: "ไม่พบข้อมูลผู้ใช้",
      });
      setTimeout(() => {
        navigate("/customer");
      }, 2000);
    }
  };

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
    if (fileList.length > 0) {
      values.Profile = fileList[0].thumbUrl;
    }
    const payload = {
      ...values,
    };

    const res = await UpdateUsersById(id, payload);
    if (res.status === 200) {
      messageApi.open({
        type: "success",
        content: res.data.message,
      });
      setTimeout(() => {
        navigate("/customer");
      }, 2000);
    } else {
      messageApi.open({
        type: "error",
        content: res.data.error,
      });
    }
  };

  useEffect(() => {
    getUserById(id);
  }, [id]);

  return (
    <div>
      {contextHolder}
      <Card>
        <h2>แก้ไขข้อมูล ผู้ดูแลระบบ</h2>
        <Divider />
        <Form
          name="basic"
          form={form}
          layout="vertical"
          onFinish={onFinish}
          autoComplete="off"
        >
          <Row gutter={[16, 0]}>
            <Col xs={24} sm={24} md={24} lg={24} xl={12}>
              <Form.Item
                label="ชื่อจริง"
                name="first_name"
                rules={[
                  {
                    required: true,
                    message: "กรุณากรอกชื่อ !",
                  },
                ]}
              >
                <Input />
              </Form.Item>
            </Col>
            <Col xs={24} sm={24} md={24} lg={24} xl={12}>
              <Form.Item
                label="นามกสุล"
                name="last_name"
                rules={[
                  {
                    required: true,
                    message: "กรุณากรอกนามสกุล !",
                  },
                ]}
              >
                <Input />
              </Form.Item>
            </Col>
            <Col xs={24} sm={24} md={24} lg={24} xl={12}>
              <Form.Item
                label="อีเมล"
                name="email"
                rules={[
                  {
                    type: "email",
                    message: "รูปแบบอีเมลไม่ถูกต้อง !",
                  },
                  {
                    required: true,
                    message: "กรุณากรอกอีเมล !",
                  },
                ]}
              >
                <Input />
              </Form.Item>
            </Col>
            <Col xs={24} sm={24} md={24} lg={24} xl={12}>
              <Form.Item
                label="วัน/เดือน/ปี เกิด"
                name="birthday"
                rules={[
                  {
                    required: true,
                    message: "กรุณาเลือกวัน/เดือน/ปี เกิด !",
                  },
                ]}
              >
                <DatePicker style={{ width: "100%" }} />
              </Form.Item>
            </Col>
            <Col xs={24} sm={24} md={24} lg={24} xl={12}>
              <Form.Item
                label="อายุ"
                name="age"
                rules={[
                  {
                    required: true,
                    message: "กรุณากรอกอายุ !",
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
            <Col xs={24} sm={24} md={24} lg={24} xl={12}>
              <Form.Item
                label="เพศ"
                name="gender_id"
                rules={[
                  {
                    required: true,
                    message: "กรุณาเลือกเพศ !",
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
            <Col xs={24} sm={24} md={24} lg={24} xl={12}>
              <Form.Item
                label="ที่อยู่"
                name="address"
                rules={[
                  {
                    required: true,
                    message: "กรุณากรอกที่อยู่ !",
                  },
                ]}
              >
                <Input />
              </Form.Item>
            </Col>
            <Col xs={24} sm={24} md={24} lg={24} xl={12}>
              <Form.Item
                label="หมวดหมู่"
                name="Category"
                rules={[
                  {
                    required: true,
                    message: "กรุณากรอกหมวดหมู่ !",
                  },
                ]}
              >
                <Input />
              </Form.Item>
            </Col>
            <Col xs={24} sm={24} md={24} lg={24} xl={12}>
              <Form.Item
                label="ค่าจ้าง"
                name="Wages"
                rules={[
                  {
                    required: true,
                    message: "กรุณากรอกค่าจ้าง !",
                  },
                ]}
              >
                <InputNumber
                  min={0}
                  max={10000000}
                  defaultValue={0}
                  style={{ width: "100%" }}
                />
              </Form.Item>
            </Col>
            <Col xs={24} sm={24} md={24} lg={24} xl={12}>
              <Form.Item
                label="เบอร์โทรศัพท์"
                name="Contact"
                rules={[
                  {
                    required: true,
                    message: "กรุณากรอกเบอร์โทรศัพท์ !",
                  },
                ]}
              >
                <Input />
              </Form.Item>
            </Col>
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
            <Col style={{ marginTop: "10px" }}>
              <Space size="middle">
                <Button type="default">
                  <Link to="/customer">ย้อนกลับ</Link>
                </Button>
                <Button type="primary" htmlType="submit">
                  บันทึก
                </Button>
              </Space>
            </Col>
          </Row>
        </Form>
      </Card>
    </div>
  );
}

export default CustomerEdit;
