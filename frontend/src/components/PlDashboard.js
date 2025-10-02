import React, { useState, useEffect } from 'react';
import api from '../axiosConfig';
import '../App.css';

const PlDashboard = () => {
  const [state, setState] = useState({
    courses: [],
    classes: [],
    lecturers: [],
    error: '',
    success: '',
    activeView: 'overview',
    expandedItems: {
      courses: {},
      classes: {}
    }
  });

  const [forms, setForms] = useState({
    course: { name: '', code: '', facultyName: '' },
    class: { name: '', courseId: '', lecturerId: '' }
  });

  const [loading, setLoading] = useState({
    courses: false,
    classes: false,
    lecturers: false,
    courseSubmit: false,
    classSubmit: false,
    export: false
  });

  const [pagination, setPagination] = useState({
    courses: 0,
    classes: 0
  });

  const itemsPerPage = 6;

  useEffect(() => {
    fetchAllData();
  }, []);

  const setStateField = (field, value) => {
    setState(prev => ({ ...prev, [field]: value }));
  };

  const setFormsField = (formType, field, value) => {
    setForms(prev => ({
      ...prev,
      [formType]: {
        ...prev[formType],
        [field]: value
      }
    }));
  };

  const setLoadingField = (field, value) => {
    setLoading(prev => ({ ...prev, [field]: value }));
  };

  const showMessage = (type, message, duration = 5000) => {
    setStateField(type, message);
    setTimeout(() => setStateField(type, ''), duration);
  };

  const switchView = (viewName) => {
    setStateField('activeView', viewName);
    setPagination({ courses: 0, classes: 0 });
  };

  const toggleExpand = (section, itemId) => {
    setStateField('expandedItems', {
      ...state.expandedItems,
      [section]: {
        ...state.expandedItems[section],
        [itemId]: !state.expandedItems[section][itemId]
      }
    });
  };

  const nextPage = (type) => {
    setPagination(prev => ({
      ...prev,
      [type]: prev[type] + 1
    }));
  };

  const prevPage = (type) => {
    setPagination(prev => ({
      ...prev,
      [type]: Math.max(0, prev[type] - 1)
    }));
  };

  const canNext = (items, type) => {
    return (pagination[type] + 1) * itemsPerPage < items.length;
  };

  const canPrev = (type) => {
    return pagination[type] > 0;
  };

  const getPaginatedItems = (items, type) => {
    const startIndex = pagination[type] * itemsPerPage;
    return items.slice(startIndex, startIndex + itemsPerPage);
  };

  const fetchAllData = async () => {
    await Promise.all([
      fetchCourses(),
      fetchClasses(),
      fetchLecturers()
    ]);
  };

  const fetchCourses = async () => {
    setLoadingField('courses', true);
    try {
      const res = await api.get('/courses');
      setStateField('courses', res.data || []);
    } catch (err) {
      showMessage('error', 'Failed to fetch courses: ' + (err.response?.data?.message || err.message));
    } finally {
      setLoadingField('courses', false);
    }
  };

  const fetchClasses = async () => {
    setLoadingField('classes', true);
    try {
      const res = await api.get('/classes');
      setStateField('classes', res.data || []);
    } catch (err) {
      showMessage('error', 'Failed to fetch classes: ' + (err.response?.data?.message || err.message));
    } finally {
      setLoadingField('classes', false);
    }
  };

  const fetchLecturers = async () => {
    setLoadingField('lecturers', true);
    try {
      const res = await api.get('/lecturers');
      setStateField('lecturers', res.data || []);
    } catch (err) {
      showMessage('error', 'Failed to fetch lecturers: ' + (err.response?.data?.message || err.message));
    } finally {
      setLoadingField('lecturers', false);
    }
  };

  const validateCourseForm = () => {
    const { name, code, facultyName } = forms.course;
    
    if (!name.trim() || !code.trim() || !facultyName.trim()) {
      showMessage('error', 'All course fields are required');
      return false;
    }

    if (name.trim().length < 2) {
      showMessage('error', 'Course name must be at least 2 characters long');
      return false;
    }

    if (code.trim().length < 3) {
      showMessage('error', 'Course code must be at least 3 characters long');
      return false;
    }

    return true;
  };

  const validateClassForm = () => {
    const { name, courseId, lecturerId } = forms.class;
    
    if (!name.trim() || !courseId || !lecturerId) {
      showMessage('error', 'All class fields are required');
      return false;
    }

    if (name.trim().length < 2) {
      showMessage('error', 'Class name must be at least 2 characters long');
      return false;
    }

    return true;
  };

  const submitCourse = async () => {
    if (!validateCourseForm()) return;

    setLoadingField('courseSubmit', true);
    try {
      await api.post('/courses', forms.course);
      
      showMessage('success', 'Course added successfully!');
      setFormsField('course', 'name', '');
      setFormsField('course', 'code', '');
      setFormsField('course', 'facultyName', '');
      fetchCourses();
    } catch (err) {
      showMessage('error', 'Failed to add course: ' + (err.response?.data?.message || err.message));
    } finally {
      setLoadingField('courseSubmit', false);
    }
  };

  const submitClass = async () => {
    if (!validateClassForm()) return;

    setLoadingField('classSubmit', true);
    try {
      await api.post('/classes', forms.class);
      
      showMessage('success', 'Class assigned successfully!');
      setFormsField('class', 'name', '');
      setFormsField('class', 'courseId', '');
      setFormsField('class', 'lecturerId', '');
      fetchClasses();
    } catch (err) {
      showMessage('error', 'Failed to assign class: ' + (err.response?.data?.message || err.message));
    } finally {
      setLoadingField('classSubmit', false);
    }
  };

  const handleExportReports = async () => {
    setLoadingField('export', true);
    try {
      const res = await api.get('/reports/export', { responseType: 'blob' });
      
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `academic_reports_${new Date().toISOString().split('T')[0]}.xlsx`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      
      showMessage('success', 'Reports exported successfully!');
    } catch (err) {
      showMessage('error', 'Failed to export reports: ' + (err.response?.data?.message || err.message));
    } finally {
      setLoadingField('export', false);
    }
  };

  const { courses, classes, lecturers, error, success, activeView, expandedItems } = state;
  const { course: courseForm, class: classForm } = forms;

  return (
    <div className="pl-dashboard">
      {error && <div className="col-12"><div className="auth-error">{error}</div></div>}
      {success && <div className="col-12"><div className="auth-success">{success}</div></div>}

      {/* View Navigation */}
      <div className="view-navigation">
        <div className="view-buttons">
          <button 
            className={`view-button ${activeView === 'overview' ? 'active' : ''}`}
            onClick={() => switchView('overview')}
          >
            <i className="fas fa-chart-pie me-2"></i>
            Overview
          </button>
          <button 
            className={`view-button ${activeView === 'courses' ? 'active' : ''}`}
            onClick={() => switchView('courses')}
          >
            <i className="fas fa-book me-2"></i>
            Courses ({courses.length})
          </button>
          <button 
            className={`view-button ${activeView === 'classes' ? 'active' : ''}`}
            onClick={() => switchView('classes')}
          >
            <i className="fas fa-users me-2"></i>
            Classes ({classes.length})
          </button>
          <button 
            className={`view-button ${activeView === 'management' ? 'active' : ''}`}
            onClick={() => switchView('management')}
          >
            <i className="fas fa-cogs me-2"></i>
            Management
          </button>
        </div>
      </div>

      {/* Overview View */}
      {activeView === 'overview' && (
        <div className="overview-view">
          {/* Recent Activity - Now the main content of overview */}
          <div className="recent-activity">
            <h3 className="section-title">Recent Activity</h3>
            <div className="activity-grid">
              {courses.slice(0, 3).map((course) => (
                <div key={course.id} className="activity-card">
                  <div className="activity-icon">
                    <i className="fas fa-book text-primary"></i>
                  </div>
                  <div className="activity-content">
                    <h4>{course.name}</h4>
                    <p>Code: {course.code}</p>
                    <small>Faculty: {course.faculty_name}</small>
                  </div>
                </div>
              ))}
              {classes.slice(0, 3).map((classItem) => (
                <div key={classItem.id} className="activity-card">
                  <div className="activity-icon">
                    <i className="fas fa-users text-success"></i>
                  </div>
                  <div className="activity-content">
                    <h4>{classItem.name}</h4>
                    <p>Course: {classItem.course_name || 'Not assigned'}</p>
                    <small>Lecturer: {classItem.lecturer_name || 'Unassigned'}</small>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Courses View */}
      {activeView === 'courses' && (
        <div className="courses-view">
          <div className="view-header">
            <h2>Course Management</h2>
            <p>Manage all academic courses in the system</p>
          </div>

          {loading.courses ? (
            <div className="loading">
              <div className="loading-spinner"></div>
              <p className="mt-2">Loading courses...</p>
            </div>
          ) : courses.length > 0 ? (
            <>
              <div className="courses-grid">
                {getPaginatedItems(courses, 'courses').map((course) => (
                  <div key={course.id} className="course-card">
                    <div className="course-header">
                      <h3>{course.name}</h3>
                    </div>
                    <div className="course-details">
                      <div className="detail-item">
                        <i className="fas fa-code"></i>
                        <span><strong>Code:</strong> {course.code}</span>
                      </div>
                      <div className="detail-item">
                        <i className="fas fa-building"></i>
                        <span><strong>Faculty:</strong> {course.faculty_name}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              {/* Pagination */}
              {courses.length > itemsPerPage && (
                <div className="pagination">
                  <button 
                    className="btn btn-outline"
                    onClick={() => prevPage('courses')}
                    disabled={!canPrev('courses')}
                  >
                    <i className="fas fa-chevron-left"></i> Previous
                  </button>
                  <span className="page-info">
                    Page {pagination.courses + 1} of {Math.ceil(courses.length / itemsPerPage)}
                  </span>
                  <button 
                    className="btn btn-outline"
                    onClick={() => nextPage('courses')}
                    disabled={!canNext(courses, 'courses')}
                  >
                    Next <i className="fas fa-chevron-right"></i>
                  </button>
                </div>
              )}
            </>
          ) : (
            <div className="empty-state">
              <i className="fas fa-book fa-3x mb-3"></i>
              <h3>No Courses Available</h3>
              <p>Get started by adding your first course.</p>
              <button 
                className="btn btn-primary mt-3"
                onClick={() => switchView('management')}
              >
                <i className="fas fa-plus me-2"></i>
                Add First Course
              </button>
            </div>
          )}
        </div>
      )}

      {/* Classes View - Updated with Cards Layout */}
      {activeView === 'classes' && (
        <div className="classes-view">
          <div className="view-header">
            <h2>Class Management</h2>
            <p>Manage class assignments and lecturer allocations</p>
          </div>

          {loading.classes ? (
            <div className="loading">
              <div className="loading-spinner"></div>
              <p className="mt-2">Loading classes...</p>
            </div>
          ) : classes.length > 0 ? (
            <>
              <div className="classes-grid">
                {getPaginatedItems(classes, 'classes').map((classItem) => (
                  <div key={classItem.id} className="class-card">
                    <div className="class-card-header">
                      <div className="class-title">
                        <h3>{classItem.name}</h3>
                        <span className={`status-badge ${
                          classItem.lecturer_name ? 'assigned' : 'unassigned'
                        }`}>
                          {classItem.lecturer_name ? 'Assigned' : 'Unassigned'}
                        </span>
                      </div>
                    </div>
                    
                    <div className="class-card-body">
                      <div className="class-info-item">
                        <div className="info-icon">
                          <i className="fas fa-book"></i>
                        </div>
                        <div className="info-content">
                          <div className="info-label">Course</div>
                          <div className="info-value">
                            {classItem.course_name || 'Not assigned'}
                          </div>
                        </div>
                      </div>

                      <div className="class-info-item">
                        <div className="info-icon">
                          <i className="fas fa-chalkboard-teacher"></i>
                        </div>
                        <div className="info-content">
                          <div className="info-label">Lecturer</div>
                          <div className="info-value">
                            {classItem.lecturer_name || 'Unassigned'}
                          </div>
                        </div>
                      </div>

                      {classItem.total_students !== undefined && (
                        <div className="class-info-item">
                          <div className="info-icon">
                            <i className="fas fa-user-graduate"></i>
                          </div>
                          <div className="info-content">
                            <div className="info-label">Students</div>
                            <div className="info-value">
                              {classItem.total_students || 0} enrolled
                            </div>
                          </div>
                        </div>
                      )}
                    </div>

                    <div className="class-card-footer">
                      <div className="class-actions">
                        {!classItem.lecturer_name && (
                          <button className="btn btn-primary w-100">
                            <i className="fas fa-user-plus me-1"></i>
                            Assign Lecturer
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              {/* Pagination */}
              {classes.length > itemsPerPage && (
                <div className="pagination">
                  <button 
                    className="btn btn-outline"
                    onClick={() => prevPage('classes')}
                    disabled={!canPrev('classes')}
                  >
                    <i className="fas fa-chevron-left"></i> Previous
                  </button>
                  <span className="page-info">
                    Page {pagination.classes + 1} of {Math.ceil(classes.length / itemsPerPage)}
                  </span>
                  <button 
                    className="btn btn-outline"
                    onClick={() => nextPage('classes')}
                    disabled={!canNext(classes, 'classes')}
                  >
                    Next <i className="fas fa-chevron-right"></i>
                  </button>
                </div>
              )}
            </>
          ) : (
            <div className="empty-state">
              <i className="fas fa-users fa-3x mb-3"></i>
              <h3>No Classes Managed</h3>
              <p>Start by assigning classes to lecturers.</p>
              <button 
                className="btn btn-primary mt-3"
                onClick={() => switchView('management')}
              >
                <i className="fas fa-link me-2"></i>
                Assign First Class
              </button>
            </div>
          )}
        </div>
      )}

      {/* Management View */}
      {activeView === 'management' && (
        <div className="management-view">
          <div className="view-header">
            <h2>System Management</h2>
            <p>Add courses and assign classes to lecturers</p>
          </div>

          <div className="management-grid">
            {/* Add Course Form */}
            <div className="management-card">
              <div className="card-header">
                <i className="fas fa-plus-circle me-2"></i>
                Add New Course
              </div>
              <div className="card-body">
                <div className="form-group">
                  <label className="form-label">Course Name</label>
                  <input
                    type="text"
                    placeholder="e.g., Advanced Web Development"
                    value={courseForm.name}
                    onChange={(e) => setFormsField('course', 'name', e.target.value)}
                    className="form-control"
                    disabled={loading.courseSubmit}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Course Code</label>
                  <input
                    type="text"
                    placeholder="e.g., CSE456"
                    value={courseForm.code}
                    onChange={(e) => setFormsField('course', 'code', e.target.value)}
                    className="form-control"
                    disabled={loading.courseSubmit}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Faculty Name</label>
                  <input
                    type="text"
                    placeholder="e.g., Faculty of Computer Science"
                    value={courseForm.facultyName}
                    onChange={(e) => setFormsField('course', 'facultyName', e.target.value)}
                    className="form-control"
                    disabled={loading.courseSubmit}
                  />
                </div>

                <button
                  onClick={submitCourse}
                  className="btn btn-primary w-100"
                  disabled={loading.courseSubmit}
                >
                  {loading.courseSubmit ? (
                    <>
                      <div className="loading-spinner"></div>
                      Adding Course...
                    </>
                  ) : (
                    <>
                      <i className="fas fa-save me-1"></i>
                      Add Course
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Assign Class Form */}
            <div className="management-card">
              <div className="card-header">
                <i className="fas fa-link me-2"></i>
                Assign Class to Lecturer
              </div>
              <div className="card-body">
                <div className="form-group">
                  <label className="form-label">Class Name</label>
                  <input
                    type="text"
                    placeholder="e.g., Web Dev Spring 2024"
                    value={classForm.name}
                    onChange={(e) => setFormsField('class', 'name', e.target.value)}
                    className="form-control"
                    disabled={loading.classSubmit}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Select Course</label>
                  <select
                    value={classForm.courseId}
                    onChange={(e) => setFormsField('class', 'courseId', e.target.value)}
                    className="form-control"
                    disabled={loading.classSubmit}
                  >
                    <option value="">Choose a course...</option>
                    {courses.map((c) => (
                      <option key={c.id} value={c.id}>
                        {c.name} ({c.code})
                      </option>
                    ))}
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label">Assign Lecturer</label>
                  <select
                    value={classForm.lecturerId}
                    onChange={(e) => setFormsField('class', 'lecturerId', e.target.value)}
                    className="form-control"
                    disabled={loading.classSubmit}
                  >
                    <option value="">Select a lecturer...</option>
                    {lecturers.map((lecturer) => (
                      <option key={lecturer.id} value={lecturer.id}>
                        {lecturer.name} ({lecturer.email || 'No email'})
                      </option>
                    ))}
                  </select>
                </div>

                <button
                  onClick={submitClass}
                  className="btn btn-primary w-100"
                  disabled={loading.classSubmit || !classForm.courseId || !classForm.lecturerId}
                >
                  {loading.classSubmit ? (
                    <>
                      <div className="loading-spinner"></div>
                      Assigning Class...
                    </>
                  ) : (
                    <>
                      <i className="fas fa-user-plus me-1"></i>
                      Assign Class
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Export Reports */}
            <div className="management-card">
              <div className="card-header">
                <i className="fas fa-download me-2"></i>
                Export Reports
              </div>
              <div className="card-body text-center">
                <div className="export-content">
                  <i className="fas fa-file-excel fa-3x text-success mb-3"></i>
                  <h5 className="text-success">Export Academic Reports</h5>
                  <p className="text-muted small">
                    Download comprehensive Excel reports with all academic data, 
                    attendance records, and performance metrics.
                  </p>
                  <button
                    onClick={handleExportReports}
                    className="btn btn-success w-100 mt-3"
                    disabled={loading.export}
                  >
                    {loading.export ? (
                      <>
                        <div className="loading-spinner"></div>
                        Preparing Download...
                      </>
                    ) : (
                      <>
                        <i className="fas fa-file-excel me-1"></i>
                        Export to Excel
                      </>
                    )}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default PlDashboard;