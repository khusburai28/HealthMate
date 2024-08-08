import React from 'react';
import {BrowserRouter, Routes, Route, Navigate, useParams} from 'react-router-dom';
import Navbar from './compnents/navbar/Navbar';
import Home from './compnents/home/Home';
import Profile from './compnents/profile/Profile';
import NotFound from './compnents/notFound/NotFound';
import Signup from './compnents/SignupIn/Signup';
import Login from './compnents/login/Login';
import NoAccess from './compnents/noAccess/NoAccess';
import ProfileUpdate from './compnents/profile/ProfileUpdate';
import AnonymousSharing from './compnents/anonymous/AnonymousSharing';
import AnonymousPost from './compnents/anonymous/AnonymousPost';
import AllAnonymousPost from './compnents/anonymous/AllAnonymousPost';
import AboutUs from './compnents/aboutUs/AboutUs';
import Createjournal from './compnents/journal/Createjournal.jsx';
import Readjournal from './compnents/journal/Readjournal.jsx';
import JournalDetail from './compnents/journal/Readonejournal.jsx';
import MoodTrack from './compnents/moodtrack/MoodTrack.jsx';
import Quiz from './compnents/quiz/Quiz.jsx';
import UpdateJournal from './compnents/journal/Updatejournal.jsx';
import Therapist from './compnents/AITherapist/Therapist.jsx';

const PrivateRoute = ({ children }) => {
  const { username: usernameFromUrl } = useParams(); // Extract username from URL
  const token = localStorage.getItem('token');
  const usernameFromStorage = localStorage.getItem('tokenUser');

  if (!token || usernameFromUrl !== usernameFromStorage) {
    localStorage.removeItem('token');
    localStorage.removeItem('tokenUser');
    return <Navigate to="/unauthorizedAccess" />;
  }

  return children;
};

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/:username/profile" element={<PrivateRoute><Profile /></PrivateRoute>} />
        <Route path="/signup" element={<Signup />} />
        <Route path="/login" element={<Login />} />
        <Route path="/unauthorizedAccess" element={<NoAccess />} />
        <Route path="/:username/updateprofile" element={<PrivateRoute><ProfileUpdate /></PrivateRoute>} />
        <Route path="/:username/anonymoussharing" element={<PrivateRoute><AnonymousSharing /></PrivateRoute>} />
        <Route path="/:username/createanonymouspost" element={<PrivateRoute><AnonymousPost /></PrivateRoute>} />
        <Route path="/:username/allanonymousposts" element={<PrivateRoute><AllAnonymousPost /></PrivateRoute>} />
        <Route path="/:username/mood" element={<PrivateRoute><MoodTrack /></PrivateRoute>} />
        <Route path="/:username/quiz" element={<PrivateRoute><Quiz /></PrivateRoute>} />
        <Route path="/:username/therapist" element={<PrivateRoute><Therapist /></PrivateRoute>} />
        <Route path="/aboutus" element={<AboutUs />} />
        


        <Route path='/:username/createjournal' element={<PrivateRoute><Createjournal /></PrivateRoute>} />
        <Route path='/:username/readjournals' element={<PrivateRoute><Readjournal /></PrivateRoute>} />
        <Route path='/:username/readjournals/:id' element={<PrivateRoute><JournalDetail /></PrivateRoute>} />
        <Route path="/:username/journals/:id/edit" element={<PrivateRoute><UpdateJournal /> </PrivateRoute>} />

        <Route path="*" element={<NotFound />} />
      </Routes>
      </BrowserRouter>
  );
}

export default App;
