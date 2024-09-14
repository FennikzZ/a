import { LoadingOutlined } from "@ant-design/icons";

const Loader: React.FC = () => (
  <div
    style={{
      position: "fixed",
      top: "50%",
      left: "50%",
      transform: "translate(-50%, -50%)",
      zIndex: 2000,
      width: "100%",
      height: "100%",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      background: "rgba(255, 255, 255, 0.8)", // semi-transparent background
      borderRadius: "8px", // rounded corners
    }}
  >
    <LoadingOutlined
      style={{
        fontSize: 80,
        color: "#007bff", // change color to a blue shade
      }}
      spin
    />
    <p
      style={{
        marginTop: "20px",
        fontSize: "18px",
        color: "#333", // dark text color for contrast
        fontWeight: "500",
      }}
    >
      Loading, please wait...
    </p>
  </div>
);

export default Loader;
