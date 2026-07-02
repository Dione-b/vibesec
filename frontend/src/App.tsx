import { Route, Routes } from "react-router";
import { SkeletonTheme } from "react-loading-skeleton";
import "react-loading-skeleton/dist/skeleton.css";
import Layout from "./components/Layout";
import Home from "./pages/Home";
import Report from "./pages/Report";

export default function App() {
  return (
    <SkeletonTheme baseColor="#121a2e" highlightColor="#2a3555" borderRadius={12}>
      <Layout>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/reports/:id" element={<Report />} />
        </Routes>
      </Layout>
    </SkeletonTheme>
  );
}
