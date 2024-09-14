import React, { useState, useEffect } from "react";
import { Col, Row, Divider, message, Input, Typography, Select, Avatar, Pagination } from "antd";
import { GetPostwork } from "../../services/https/index";
import { PostworkInterface } from "../../interfaces/Postwork";
import videoBg from "../../assets/back.mp4"; // Background video

const { Search } = Input;
const { Option } = Select;
const { TextArea } = Input;

function PostworkList() {
  const [postworks, setPostworks] = useState<PostworkInterface[]>([]);
  const [filteredPostworks, setFilteredPostworks] = useState<PostworkInterface[]>([]);
  const [categories, setCategories] = useState<string[]>([]);
  const [messageApi, contextHolder] = message.useMessage();
  const [searchTerm, setSearchTerm] = useState<string>("");
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [noResultsFound, setNoResultsFound] = useState<boolean>(false);

  // Pagination state
  const [currentPage, setCurrentPage] = useState<number>(1);
  const pageSize = 5; // Number of items per page

  const getPostworks = async () => {
    try {
      let res = await GetPostwork();
      if (res.status === 200) {
        setPostworks(res.data);
        setFilteredPostworks(res.data);

        // Extract unique categories
        const uniqueCategories = Array.from(
          new Set(res.data.map((postwork) => postwork.Work?.category || ""))
        ).filter((category) => category !== ""); // Remove empty categories if any
        setCategories(uniqueCategories);
      } else {
        setPostworks([]);
        setFilteredPostworks([]);
        messageApi.open({
          type: "error",
          content: res.data.error,
        });
      }
    } catch (error) {
      messageApi.open({
        type: "error",
        content: "Failed to fetch postworks",
      });
    }
  };

  const handleSearch = (value: string) => {
    setSearchTerm(value);
    const searchTerms = value.toLowerCase().split(/\s+/); // Split by any whitespace

    const filtered = postworks.filter(
      (postwork) => {
        const userName = `${postwork.User?.first_name || ""} ${postwork.User?.last_name || ""}`.toLowerCase();
        const workInfo = postwork.Work?.info.toLowerCase() || "";

        return searchTerms.every(term =>
          userName.includes(term) || workInfo.includes(term)
        );
      }
    );

    const result = selectedCategory
      ? filtered.filter((postwork) => postwork.Work?.category === selectedCategory)
      : filtered;

    setFilteredPostworks(result);
    setNoResultsFound(result.length === 0);
    setCurrentPage(1); // Reset to the first page on new search
  };

  const handleSearchChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    handleSearch(event.target.value);
  };

  const handleSelectChange = (value: string | null) => {
    setSelectedCategory(value);
    const filtered = postworks.filter(
      (postwork) =>
        (!value || postwork.Work?.category === value) &&
        (!searchTerm ||
          `${postwork.User?.first_name || ""} ${postwork.User?.last_name || ""}`.toLowerCase().includes(searchTerm.toLowerCase()) ||
          (postwork.Work?.info.toLowerCase() || "").includes(searchTerm.toLowerCase()))
    );
    setFilteredPostworks(filtered);
    setNoResultsFound(filtered.length === 0);
    setCurrentPage(1); // Reset to the first page on new filter
  };

  const handlePageChange = (page: number) => {
    setCurrentPage(page);
  };

  useEffect(() => {
    getPostworks();
  }, []);

  // Calculate items for the current page
  const startIndex = (currentPage - 1) * pageSize;
  const endIndex = startIndex + pageSize;
  const currentPostworks = filteredPostworks.slice(startIndex, endIndex);

  // Function to determine if the contact is a URL
  const isUrl = (str: string) => {
    const urlPattern = /^https?:\/\//;
    return urlPattern.test(str);
  };

  return (
    <>
      {contextHolder}

      {/* Background video */}
      <video
        autoPlay
        loop
        muted
        style={{
          position: "fixed",
          top: 0,
          left: 0,
          width: "100%",
          height: "100%",
          objectFit: "cover",
          zIndex: -1,
          filter: "brightness(0.6)", // Reduce brightness for contrast
        }}
      >
        <source src={videoBg} type="video/mp4" />
      </video>

      <Row justify="space-between" align="middle">
        <Col>
          <h2>HOME</h2>
          <Select
            showSearch
            placeholder="Select a category"
            style={{ width: 200, marginTop: 10 }}
            onChange={handleSelectChange}
            allowClear
            filterOption={(input, option) =>
              (option?.label ?? '').toLowerCase().includes(input.toLowerCase())
            }
            options={categories.map((category) => ({ value: category, label: category }))}
          />
        </Col>
        <Col>
          <Search
            placeholder="ค้นหาด้วยชื่อ"
            onChange={handleSearchChange}
            style={{ width: 300 }}
          />
        </Col>
      </Row>

      <Divider />

      <div style={{ marginTop: 20 }}>
        {noResultsFound ? (
          <Typography.Text style={{ display: "block", textAlign: "center", marginTop: "40px" }}>
            ไม่พบสิ่งที่ต้องการค้นหา
          </Typography.Text>
        ) : (
          currentPostworks.map((postwork) => (
            <Row key={postwork.ID} style={{ marginBottom: 20 }}>
              <Col span={24}>
                <Row align="middle">
                  <Col>
                    <Avatar
                      src={postwork.User?.Profile || undefined}
                      size={100} // Set the size of the Avatar to 100x100 pixels
                      style={{ marginRight: 10 }}
                    />
                  </Col>
                  <Col>
                    <Typography.Text strong>
                      {postwork.User?.first_name} {postwork.User?.last_name}
                    </Typography.Text>
                    {postwork.Work?.contact && (
                      <div style={{ marginTop: 10 }}>
                        {isUrl(postwork.Work?.contact) ? (
                          <a href={postwork.Work?.contact} target="_blank" rel="noopener noreferrer">
                            GO TO CONTACT
                          </a>
                        ) : (
                          <Typography.Text>{postwork.Work?.contact}</Typography.Text>
                        )}
                      </div>
                    )}
                  </Col>
                </Row>
                <TextArea
                  value={postwork.Work?.info || ""}
                  readOnly
                  rows={10}
                  style={{
                    width: "100%",
                    marginTop: 5,
                    paddingTop: 5,
                    border: "3px solid gray",  // Added gray border
                    borderRadius: 5,           // Optional: adds rounded corners
                  }}
                />
              </Col>
            </Row>
          ))
        )}
      </div>

      {/* Pagination */}
      <Row justify="center" style={{ marginTop: 20 }}>
        <Pagination
          current={currentPage}
          pageSize={pageSize}
          total={filteredPostworks.length}
          onChange={handlePageChange}
        />
      </Row>
    </>
  );
}

export default PostworkList;
