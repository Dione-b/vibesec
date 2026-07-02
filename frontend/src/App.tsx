import { Route, Routes } from "react-router";
import Layout from "./components/Layout";
import Home from "./pages/Home";
import Report from "./pages/Report";

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/reports/:id" element={<Report />} />
      </Routes>
    </Layout>
  );
}
