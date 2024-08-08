// import React, { useState, useEffect } from 'react';
// import Navbar from '../navbar/Navbar';
// import axios from 'axios';

// const AllAnonymousPost = () => {
//   const [anonymousPosts, setAnonymousPosts] = useState([]);

//   useEffect(() => {
//     const fetchAnonymousPosts = async () => {
//       try {
//         const response = await axios.get('http://localhost:8000/anonymousPosts');
//         setAnonymousPosts(response.data);
//       } catch (error) {
//         console.error('Error fetching anonymous posts:', error);
//       }
//     };
//     fetchAnonymousPosts();
//   }, []);

//   return (
//     <>
//       <Navbar />
//       <div className="container mx-auto py-8 mt-24">
//         <h1 className="text-3xl font-bold mb-6 text-center">All Anonymous Posts</h1>
//         <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
//           {anonymousPosts.map(post => (
//             <div key={post._id} className="flex flex-col bg-gradient-to-br from-blue-gray-light to-blue-gray border border-gray-200 shadow-sm rounded-xl">
//   <div className="bg-gray-100 border-b border-gray-200 rounded-t-xl py-3 px-4 md:py-4 md:px-5">
//     <p className="mt-1 text-sm text-gray-600">
//       {post.featured && 'Featured'}
//     </p>
//   </div>
//   <div className="p-4 md:p-5">
//     <h3 className="text-lg font-bold text-gray-800">
//       {post.title}
//     </h3>
//     <p className="mt-2 text-gray-600">
//       {post.article}
//     </p>
//     <div className="flex items-center mt-4">
//       <span className="text-gray-500 mr-2">Tags:</span>
//       <div className="flex flex-wrap">
//         {post.tags.map((tag, index) => (
//           <span key={index} className="m-1 bg-gray-200 hover:bg-gray-300 rounded-full px-2 font-bold text-sm leading-loose cursor-pointer">
//             {tag}
//           </span>
//         ))}
//       </div>
//     </div>
//   </div>
// </div>

//           ))}
//         </div>
//       </div>
//     </>
//   );
// };

// export default AllAnonymousPost;


import React, { useState, useEffect } from 'react';
import Navbar from '../navbar/Navbar';
import axios from 'axios';

const AllAnonymousPost = () => {
  const [anonymousPosts, setAnonymousPosts] = useState([]);

  useEffect(() => {
    const fetchAnonymousPosts = async () => {
      try {
        const response = await axios.get('http://localhost:8000/anonymousPosts');
        setAnonymousPosts(response.data);
      } catch (error) {
        console.error('Error fetching anonymous posts:', error);
      }
    };
    fetchAnonymousPosts();
  }, []);

  return (
    <>
      <Navbar />
      <div className="container mx-auto py-8 mt-24">
        <h1 className="text-3xl font-bold mb-6 text-center">All Anonymous Posts</h1>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
          {anonymousPosts.map(post => (
            <div key={post._id} className="bg-gradient-to-br from-blue-gray-light to-blue-gray border border-gray-200 shadow-sm rounded-xl overflow-hidden">
              <div className="bg-gray-100 border-b border-gray-200 rounded-t-xl py-3 px-4 md:py-4 md:px-5">
                <p className="mt-1 text-sm text-gray-600">
                  {post.featured && 'Featured'}
                </p>
              </div>
              <div className="p-4 md:p-5">
                <h3 className="text-lg font-bold text-gray-800">
                  {post.title}
                </h3>
                <p className="mt-2 text-gray-600">
                  {post.article}
                </p>
                <div className="flex items-center mt-4">
                  <span className="text-gray-500 mr-2">Tags:</span>
                  <div className="flex flex-wrap">
                    {post.tags.map((tag, index) => (
                      <span key={index} className="m-1 bg-gray-200 hover:bg-gray-300 rounded-full px-2 font-bold text-sm leading-loose cursor-pointer">
                        {tag}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </>
  );
};

export default AllAnonymousPost;



