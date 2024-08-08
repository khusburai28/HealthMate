import React, { useState, useEffect } from 'react';
import Navbar from '../navbar/Navbar';
import axios from 'axios';
import { useParams, Link } from 'react-router-dom';

import Loader from "react-js-loader";
import { Audio } from 'react-loader-spinner';
import Readjournal from '../journal/Readjournal';
import defaultProfilePicture from './download2.jpg';

const Profile = () => {
  const [userDetails, setUserDetails] = useState(null);

  // Accessing username from URL params
  const { username } = useParams();

  useEffect(() => {
    // Function to fetch user details
    const fetchUserDetails = async () => {
      try {
        const response = await axios.get(`http://localhost:8000/${username}/getuserdetails`);
        // Set user details in state
        console.log(response);
        setUserDetails(response.data);
      } catch (error) {
        console.error('Error fetching user details:', error);
      }
    };

    // Call the function to fetch user details when component mounts
    fetchUserDetails();
  }, [username]); // Fetch user details whenever username changes

  if (!userDetails) {
    // If userDetails is null, show the loader
    return (
      <div className={"mt-[25%]"}>
        <Loader type="spinner-cub" bgColor={"black"} color={"#FFFFFF"} title={"spinner-cub"} size={100} />
      </div>
    )
  }

  return (
    <>
      <Navbar />
      <main className="profile-page mt-20">
        <section className="relative block h-[500px]">
          <div
            className="absolute top-0 w-full h-full bg-center bg-cover"
            style={{
              backgroundImage: "url('https://images.unsplash.com/photo-1499336315816-097655dcfbda?ixlib=rb-1.2.1&ixid=eyJhcHBfaWQiOjEyMDd9&auto=format&fit=crop&w=2710&q=80')",
            }}
          >
            <span id="blackOverlay" className="w-full h-full absolute opacity-50 bg-black"></span>
          </div>
          <div
            className="top-auto bottom-0 left-0 right-0 w-full absolute pointer-events-none overflow-hidden h-[70px]"
            style={{ transform: 'translateZ(0px)' }}
          >
            <svg
              className="absolute bottom-0 overflow-hidden"
              xmlns="http://www.w3.org/2000/svg"
              preserveAspectRatio="none"
              version="1.1"
              viewBox="0 0 2560 100"
              x="0"
              y="0"
            >
              <polygon className="text-blueGray-200 fill-current" points="2560 0 2560 100 0 100"></polygon>
            </svg>
          </div>
        </section>
        <section className="relative py-16 bg-blueGray-200">
          <div className="container mx-auto px-4">
            <div className="relative flex flex-col min-w-0 break-words bg-white w-full mb-6 shadow-xl rounded-lg -mt-64">
              <div className="px-6">
                <div className="flex flex-wrap justify-center">
                  <div className="w-full lg:w-3/12 px-4 lg:order-2 flex justify-center">
                    <div className="relative">
                      <img
                        alt="Profile"
                        src={userDetails.profilePicture ? `http://localhost:8000/${userDetails.profilePicture}` : defaultProfilePicture}
                        className="shadow-xl rounded-full h-auto align-middle border-none absolute -m-16 -ml-20 lg:-ml-24 max-w-[180px]"
                      />
                    </div>
                  </div>
                  <div className="w-full lg:w-4/12 px-4 lg:order-3 lg:text-right lg:self-center">
                    <div className="py-6 px-3 mt-32 sm:mt-0">
                      <a
                        className="bg-blue-500 active:bg-blue-600 uppercase text-white font-bold hover:shadow-md shadow text-xs px-4 py-2 rounded outline-none focus:outline-none sm:mr-2 mb-1 ease-linear transition-all duration-150"
                        href={`/${userDetails.username}/updateprofile`}
                      >
                        Update Profile
                      </a>

                    </div>
                  </div>
                  <div className="w-full lg:w-4/12 px-4 lg:order-1">
                    <div className="flex justify-center py-4 lg:pt-4 pt-8">
                      <div className="mr-4 p-3 text-center">
                        <span className="text-xl font-bold block uppercase tracking-wide text-blueGray-600">{userDetails.journals.length}</span>
                        <span className="text-sm text-blueGray-400">Number of Journals</span>
                      </div>
                    </div>
                  </div>
                </div>
                <div className="text-center mt-12">
                  <h3 className="text-4xl font-semibold leading-normal mb-2 text-blueGray-700 mb-2">
                    {userDetails.name}
                  </h3>
                  <div className="mb-2 text-blueGray-600 mt-10">
                    <i className="fas fa-briefcase mr-2 text-lg text-blueGray-400"></i>
                    Age: {userDetails.age}
                  </div>
                  <div className="mb-2 text-blueGray-600">
                    <i className="fas fa-university mr-2 text-lg text-blueGray-400"></i>
                    Email: {userDetails.email}
                  </div>
                </div>
                <div className="mt-10 py-10 border-t border-blueGray-200 text-center">
                  <div className="flex flex-wrap justify-center">
                    <div className="w-full lg:w-9/12 px-4">
                      <p className="mb-4 text-lg leading-relaxed text-blueGray-700">
                        {userDetails.bio}
                      </p>
                    </div>
                  </div>
                  <div className="flex justify-center mt-6">
                    <Link to={`/${username}/createjournal`}>
                      <button
                        className="bg-blue-500 active:bg-blue-600 uppercase text-white font-bold hover:shadow-md shadow text-xs px-4 py-2 rounded outline-none focus:outline-none sm:mr-2 mb-1 ease-linear transition-all duration-150"
                        type="button"
                      >
                        Create Journal
                      </button>
                    </Link>

                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>
        <div className='-mt-20'>
          <Readjournal />
        </div>
      </main>
    </>
  );
};

export default Profile;
