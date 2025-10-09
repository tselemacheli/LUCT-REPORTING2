// src/components/StudentDashboard.jsx
import React, { useState, useEffect } from "react";
import api from "../api/api"; // Updated axios config
import "../App.css";

const StudentDashboard = () => {
  const [classes, setClasses] = useState([]);
  const [enrollments, setEnrollments] = useState([]);
  const [lecturers, setLecturers] = useState([]);
  const [lecturerRatings, setLecturerRatings] = useState({});
  const [selectedClassId, setSelectedClassId] = useState("");
  const [loading, setLoading] = useState({
    classes: false,
    enrollments: false,
    lecturers: false,
  });
  const [message, setMessage] = useState({ type: "", text: "" });

  // Show messages
  const showMessage = (type, text, duration = 3000) => {
    setMessage({ type, text });
    setTimeout(() => setMessage({ type: "", text: "" }), duration);
  };

  // Fetch available classes
  const fetchAvailableClasses = async () => {
    setLoading((prev) => ({ ...prev, classes: true }));
    try {
      const data = await api.get("/available-classes");
      setClasses(data);
    } catch (err) {
      showMessage("error", "Error fetching classes: " + err.message);
    } finally {
      setLoading((prev) => ({ ...prev, classes: false }));
    }
  };

  // Fetch enrolled classes
  const fetchEnrollments = async () => {
    setLoading((prev) => ({ ...prev, enrollments: true }));
    try {
      const data = await api.get("/my-enrollments");
      setEnrollments(data);
    } catch (err) {
      showMessage("error", "Error fetching enrollments: " + err.message);
    } finally {
      setLoading((prev) => ({ ...prev, enrollments: false }));
    }
  };

  // Fetch lecturers
  const fetchLecturers = async () => {
    setLoading((prev) => ({ ...prev, lecturers: true }));
    try {
      const data = await api.get("/my-lecturers");
      setLecturers(data);
    } catch (err) {
      showMessage("error", "Error fetching lecturers: " + err.message);
    } finally {
      setLoading((prev) => ({ ...prev, lecturers: false }));
    }
  };

  // Initial load
  useEffect(() => {
    fetchAvailableClasses();
    fetchEnrollments();
    fetchLecturers();
  }, []);

  // Enroll in class
  const handleEnroll = async () => {
    if (!selectedClassId) {
      showMessage("error", "Please select a class to enroll");
      return;
    }
    setLoading((prev) => ({ ...prev, enrollments: true }));
    try {
      await api.post("/enroll", { classId: selectedClassId });
      showMessage("success", "Enrolled successfully");
      setSelectedClassId("");
      fetchAvailableClasses();
      fetchEnrollments();
      fetchLecturers();
    } catch (err) {
      showMessage("error", "Error enrolling: " + err.message);
    } finally {
      setLoading((prev) => ({ ...prev, enrollments: false }));
    }
  };

  // Handle lecturer rating input changes
  const handleLecturerRatingChange = (lecturerId, field, value) => {
    setLecturerRatings((prev) => ({
      ...prev,
      [lecturerId]: {
        ...prev[lecturerId],
        [field]: value,
      },
    }));
  };

  // Submit lecturer rating
  const submitLecturerRating = async (lecturerId) => {
    const { rating, comment } = lecturerRatings[lecturerId] || {};
    if (!rating || rating < 1 || rating > 5) {
      showMessage("error", "Lecturer rating must be between 1 and 5");
      return;
    }
    setLoading((prev) => ({ ...prev, lecturers: true }));
    try {
      await api.post("/lecturer-ratings", {
        lecturerId,
        rating: Number(rating),
        comment: comment || "",
      });
      showMessage("success", "Lecturer rating submitted");
      handleLecturerRatingChange(lecturerId, "rating", "");
      handleLecturerRatingChange(lecturerId, "comment", "");
    } catch (err) {
      showMessage("error", "Error submitting rating: " + err.message);
    } finally {
      setLoading((prev) => ({ ...prev, lecturers: false }));
    }
  };

  return (
    <div className="dashboard-grid">
      {message.text && (
        <div className={`col-12 ${message.type === "error" ? "auth-error" : "auth-success"}`}>
          {message.text}
        </div>
      )}

      {/* Enrollment Section */}
      <div className="card">
        <div className="card-header">Class Enrollment</div>
        <div className="card-body dashboard-section">
          <div className="mb-4">
            <h6 className="text-primary mb-3">Enroll in a New Class</h6>
            {loading.classes ? (
              <div className="loading-spinner"></div>
            ) : (
              <>
                <select
                  className="form-control mb-3"
                  value={selectedClassId}
                  onChange={(e) => setSelectedClassId(e.target.value)}
                  disabled={loading.enrollments}
                >
                  <option value="">Select Class</option>
                  {classes.map((cl) => (
                    <option key={cl.id} value={cl.id}>
                      {cl.name} - {cl.course_name}
                    </option>
                  ))}
                </select>
                <button
                  className="btn btn-primary w-100"
                  onClick={handleEnroll}
                  disabled={loading.enrollments || !selectedClassId}
                >
                  {loading.enrollments ? "Enrolling..." : "Enroll in Class"}
                </button>
              </>
            )}
          </div>

          <div>
            <h6 className="text-primary mb-3">Your Enrolled Classes</h6>
            {loading.enrollments ? (
              <div className="loading-spinner"></div>
            ) : enrollments.length > 0 ? (
              enrollments.map((en) => (
                <div className="card mb-2 border-primary" key={en.id}>
                  <div className="card-body py-2">
                    <h6>{en.name}</h6>
                    <small className="text-muted">{en.course_name}</small>
                  </div>
                </div>
              ))
            ) : (
              <div className="text-center text-muted py-3">
                <i className="fas fa-inbox fa-2x mb-2"></i>
                <p>No enrolled classes found</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Lecturer Rating Section */}
      <div className="card">
        <div className="card-header">Rate Your Lecturers</div>
        <div className="card-body dashboard-section">
          {loading.lecturers ? (
            <div className="loading-spinner"></div>
          ) : lecturers.length > 0 ? (
            lecturers.map((lect) => (
              <div key={lect.id} className="card mb-3 border-warning">
                <div className="card-body">
                  <h6 className="text-warning mb-3">Rate {lect.name}</h6>
                  <div className="row g-2 align-items-center">
                    <div className="col-md-3">
                      <input
                        type="number"
                        min="1"
                        max="5"
                        className="form-control"
                        placeholder="1-5"
                        value={lecturerRatings[lect.id]?.rating || ""}
                        onChange={(e) => handleLecturerRatingChange(lect.id, "rating", e.target.value)}
                      />
                    </div>
                    <div className="col-md-6">
                      <input
                        type="text"
                        className="form-control"
                        placeholder="Optional comment"
                        value={lecturerRatings[lect.id]?.comment || ""}
                        onChange={(e) => handleLecturerRatingChange(lect.id, "comment", e.target.value)}
                      />
                    </div>
                    <div className="col-md-3">
                      <button
                        className="btn btn-warning w-100"
                        onClick={() => submitLecturerRating(lect.id)}
                        disabled={loading.lecturers || !lecturerRatings[lect.id]?.rating}
                      >
                        Submit
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            ))
          ) : (
            <div className="text-center text-muted py-4">
              <i className="fas fa-users fa-2x mb-2"></i>
              <p>No lecturers available to rate</p>
              <small>Enroll in classes to see your lecturers</small>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default StudentDashboard;
