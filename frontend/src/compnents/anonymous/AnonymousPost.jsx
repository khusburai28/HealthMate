import React, { useState } from 'react';
import Navbar from '../navbar/Navbar';
import { useNavigate } from 'react-router-dom';

const AnonymousPost = () => {
  const [title, setTitle] = useState('');
  const [article, setArticle] = useState('');
  const [tags, setTags] = useState('');
  const user = localStorage.getItem('tokenUser');
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();

    const postData = {
      title,
      article,
      tags: tags.split(',').map(tag => tag.trim())
    };

    try {
      const response = await fetch('http://localhost:8000/createAnonymousPosts', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${user}`
        },
        body: JSON.stringify(postData)
      });

      if (response.ok) {
        const newPost = await response.json();
        console.log('Post created:', newPost);
        // Clear the form
        setTitle('');
        setArticle('');
        setTags('');
        navigate(`/${user}/anonymoussharing`);
      } else {
        console.error('Failed to create post');
      }
    } catch (error) {
      console.error('Error:', error);
    }
  };

  return (
    <>
      <Navbar />
      <div className='w-screen mt-[13%]'>
        <div className="heading text-center font-bold text-2xl m-5 text-gray-800">New Anonymous Post</div>
        <div className="editor mx-auto w-full sm:w-10/12 lg:w-8/12 xl:w-7/12 2xl:w-6/12 flex flex-col text-gray-800 border border-gray-300 p-4 shadow-lg">
          <form onSubmit={handleSubmit} className="flex flex-col space-y-4">
            <input
              className="title bg-gray-100 border border-gray-300 p-2 outline-none"
              spellCheck="false"
              placeholder="Title"
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
            />
            <textarea
              className="description bg-gray-100 border border-gray-300 p-2 h-40 outline-none resize-none"
              spellCheck="false"
              placeholder="Describe everything about this post here"
              value={article}
              onChange={(e) => setArticle(e.target.value)}
            />
            <input
              className="tags bg-gray-100 border border-gray-300 p-2 outline-none"
              spellCheck="false"
              placeholder="Tags (comma separated)"
              type="text"
              value={tags}
              onChange={(e) => setTags(e.target.value)}
            />
            <div className="flex flex-col sm:flex-row sm:justify-between">
              <button
                type="button"
                className="btn border border-gray-300 p-1 px-4 font-semibold cursor-pointer text-gray-500"
                onClick={() => {
                  setTitle('');
                  setArticle('');
                  setTags('');
                }}
              >
                Cancel
              </button>
              <button
                type="submit"
                className="btn border border-indigo-500 p-1 px-4 font-semibold cursor-pointer text-white bg-indigo-500"
              >
                Post
              </button>
            </div>
          </form>
        </div>
      </div>
    </>
  );
};

export default AnonymousPost;
