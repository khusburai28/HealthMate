// import React, { useEffect, useState } from 'react';
// import { useNavigate, useParams } from 'react-router-dom';
// import { PhotoIcon } from '@heroicons/react/24/solid';
// import axios from 'axios';

// const UpdateJournal = () => {
//     const [title, setTitle] = useState('');
//     const [article, setArticle] = useState('');
//     const [tags, setTags] = useState('');
//     const [coverPicture, setCoverPicture] = useState(null);
//     const [error, setError] = useState('');
//     const { username, id } = useParams();
//     const navigate = useNavigate();

//     useEffect(() => {
//         const fetchJournal = async () => {
//             try {
//                 const response = await axios.get(`http://localhost:8000/${username}/${id}`);
//                 if (response.status === 200) {
//                     const { title, article, tags, coverPicture } = response.data;
//                     setTitle(title);
//                     setArticle(article);
//                     setTags(tags.join(', ')); // Convert array to comma-separated string
//                     setCoverPicture(coverPicture); // Assuming coverPicture is a URL
//                 } else {
//                     setError('Failed to fetch journal details');
//                 }
//             } catch (error) {
//                 console.error('Error fetching journal:', error);
//                 setError('Failed to fetch journal details');
//             }
//         };

//         fetchJournal();
//     }, [username, id]);

//     const handleChange = (e) => {
//         const { name, value } = e.target;
//         console.log(name);
//         console.log(value);
//         if (name === 'title') setTitle(value);
//         if (name === 'article') setArticle(value);
//         if (name === 'tags') setTags(value);
//     };

//     const handleFileChange = (e) => {
//         setCoverPicture(e.target.files[0]);
//     };

//     const handleCancel = () => {
//         navigate(`/${username}/profile`);
//     };

//     const handleSubmit = async (e) => {
//         e.preventDefault();
//         try {
//             const formData = new FormData();
//             formData.append('title', title);
//             console.log(title);
//             formData.append('article', article);
//             formData.append('tags', tags);
//             if (coverPicture) {
//                 formData.append('coverPicture', coverPicture);
//             }
    
//             const formDataObject = {};
// for (const [key, value] of formData.entries()) {
//     formDataObject[key] = value;
// }

// // Log the key-value pairs
// console.log('Submitting form data:');
// for (const [key, value] of Object.entries(formDataObject)) {
//     console.log(`${key}: ${value}`);
// }

// // Send the request with the plain JavaScript object
// const response = await axios.put(`http://localhost:8000/journals/${username}/${id}`, formDataObject);
    
//             if (response.status !== 200) {
//                 throw new Error('Network response was not ok');
//             } else {
//                 console.log('Journal updated successfully:', response.data);
//                 navigate(`/${username}/profile`);
//             }
//         } catch (error) {
//             console.error('Error updating journal:', error);
//             setError('Failed to update journal');
//         }
//     };
    

//     return (
//         <div>
//             <div className="px-4 sm:px-6 lg:px-8 pt-20 bg-gradient-to-r from-zinc-50 to-red-100">
//                 <form className='max-w-3xl mx-auto' onSubmit={handleSubmit}>
//                     <div className="space-y-12">
//                         <div className="border-b border-gray-900/10 pb-12">
//                             <h2 className="text-2xl font-bold leading-7 text-gray-900 text-center mb-8">Update your journal!</h2>

//                             <div className="mt-10 grid grid-cols-1 gap-x-6 gap-y-8 col-span-full">
//                                 <div className="col-span-full">
//                                     <label htmlFor="coverPicture" className="block text-sm font-medium leading-6 text-gray-900">Cover Photo</label>
//                                     <div className="mt-2 flex justify-center rounded-lg border border-dashed border-gray-900/25 px-6 py-10">
//                                         <div className="text-center">
//                                             <PhotoIcon className="mx-auto h-12 w-12 text-gray-300" aria-hidden="true" />
//                                             <div className="mt-4 flex text-sm leading-6 text-gray-600">
//                                                 <label htmlFor="file-upload" className="relative cursor-pointer rounded-md bg-white font-semibold text-indigo-600 focus-within:outline-none focus-within:ring-2 focus-within:ring-indigo-600 focus-within:ring-offset-2 hover:text-indigo-500">
//                                                     <span>Upload a file</span>
//                                                     <input id="file-upload" name="coverPicture" type="file" onChange={handleFileChange} className="sr-only" />
//                                                 </label>
//                                                 <p className="pl-1">or drag and drop</p>
//                                             </div>
//                                             <p className="text-xs leading-5 text-gray-600">PNG, JPG, GIF up to 10MB</p>
//                                         </div>
//                                     </div>
//                                 </div>
//                                 <div className="sm:col-span-4">
//                                     <label htmlFor="title" className="block text-sm font-medium leading-6 text-gray-900">
//                                         Title
//                                     </label>
//                                     <div className="mt-2">
//                                         <div className="flex rounded-md shadow-sm ring-1 ring-inset ring-gray-300 focus-within:ring-2 focus-within:ring-inset focus-within:ring-indigo-600 sm:max-w-md">
//                                             <input
//                                                 type="text"
//                                                 name="title"
//                                                 id="title"
//                                                 value={title}
//                                                 onChange={handleChange}
//                                                 className="block flex-1 border-0 bg-transparent py-1.5 pl-1 text-gray-900 placeholder:text-gray-400 focus:ring-0 sm:text-sm sm:leading-6"
//                                                 placeholder="Your journal title"
//                                             />
//                                         </div>
//                                     </div>
//                                 </div>
//                                 <div className="col-span-full">
//                                     <label htmlFor="article" className="block text-sm font-medium leading-6 text-gray-900">
//                                         Your Journal
//                                     </label>
//                                     <div className="mt-2">
//                                         <textarea
//                                             id="article"
//                                             name="article"
//                                             rows={10}
//                                             value={article}
//                                             onChange={handleChange}
//                                             className="block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
//                                             placeholder="Write your journal here..."
//                                         />
//                                     </div>
//                                     <p className="mt-3 text-sm leading-6 text-gray-600">Express yourself!</p>
//                                 </div>
//                                 <div className="sm:col-span-4">
//                                     <label htmlFor="tags" className="block text-sm font-medium leading-6 text-gray-900">
//                                         Tags
//                                     </label>
//                                     <div className="mt-2">
//                                         <div className="flex rounded-md shadow-sm ring-1 ring-inset ring-gray-300 focus-within:ring-2 focus-within:ring-inset focus-within:ring-indigo-600 sm:max-w-md">
//                                             <input
//                                                 type="text"
//                                                 name="tags"
//                                                 id="tags"
//                                                 value={tags}
//                                                 onChange={handleChange}
//                                                 className="block flex-1 border-0 bg-transparent py-1.5 pl-1 text-gray-900 placeholder:text-gray-400 focus:ring-0 sm:text-sm sm:leading-6"
//                                                 placeholder="e.g., travel, food, lifestyle"
//                                             />
//                                         </div>
//                                     </div>
//                                 </div>
//                             </div>
//                         </div>
//                     </div>

//                     {error && <p className="text-red-500 text-center mt-4">{error}</p>}

//                     <div className="mt-12 flex items-center justify-center gap-x-6">
//                         <button onClick={handleCancel} type="button" className="text-lg font-semibold leading-6 text-gray-900">
//                             Cancel
//                         </button>
//                         <button
//                             type="submit"
//                             className="rounded-md bg-indigo-600 px-6 py-3 text-lg font-semibold text-white shadow-sm hover:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600">
//                             Save
//                         </button>
//                     </div>
//                 </form>
//             </div>
//         </div>
//     );
// }

// export default UpdateJournal;


import React, { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { PhotoIcon } from '@heroicons/react/24/solid';
import axios from 'axios';
import Navbar from '../navbar/Navbar';

const UpdateJournal = () => {
    const [title, setTitle] = useState('');
    const [article, setArticle] = useState('');
    const [tags, setTags] = useState('');
    const [coverPicture, setCoverPicture] = useState(null);
    const [error, setError] = useState('');
    const { username, id } = useParams();
    const navigate = useNavigate();

    useEffect(() => {
        const fetchJournal = async () => {
            try {
                const response = await axios.get(`http://localhost:8000/${username}/${id}`);
                if (response.status === 200) {
                    const { title, article, tags, coverPicture } = response.data;
                    setTitle(title);
                    setArticle(article);
                    setTags(tags.join(', ')); // Convert array to comma-separated string
                    setCoverPicture(coverPicture); // Assuming coverPicture is a URL
                } else {
                    setError('Failed to fetch journal details');
                }
            } catch (error) {
                console.error('Error fetching journal:', error);
                setError('Failed to fetch journal details');
            }
        };

        fetchJournal();
    }, [username, id]);

    const handleChange = (e) => {
        const { name, value } = e.target;
        if (name === 'title') setTitle(value);
        if (name === 'article') setArticle(value);
        if (name === 'tags') setTags(value);
    };

    const handleFileChange = (e) => {
        setCoverPicture(e.target.files[0]);
    };

    const handleCancel = () => {
        navigate(`/${username}/profile`);
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            const formData = new FormData();
            formData.append('title', title);
            formData.append('article', article);
            formData.append('tags', tags);
            if (coverPicture) {
                formData.append('coverPicture', coverPicture);
            }

            const formDataObject = {};
            for (const [key, value] of formData.entries()) {
                formDataObject[key] = value;
            }

            const response = await axios.put(`http://localhost:8000/journals/${username}/${id}`, formDataObject);
    
            if (response.status !== 200) {
                throw new Error('Network response was not ok');
            } else {
                console.log('Journal updated successfully:', response.data);
                navigate(`/${username}/profile`);
            }
        } catch (error) {
            console.error('Error updating journal:', error);
            setError('Failed to update journal');
        }
    };

    return (
        <>
        <Navbar />
        <div className="min-h-screen bg-white flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8 mt-20">
            <div className="max-w-3xl w-full bg-gray-100 rounded-lg shadow-md p-8"style={{ background: 'linear-gradient(to right, #D1D5DB, #E5E7EB, #F3F4F6)' }}>
                <h2 className="text-3xl font-bold leading-9 text-gray-900 text-center mb-8">Update your journal!</h2>
                <form className="space-y-8" onSubmit={handleSubmit}>
                    <div className="space-y-6">
                        <div>
                            <label htmlFor="title" className="block text-sm font-medium leading-6 text-gray-900">Title</label>
                            <input
                                type="text"
                                name="title"
                                id="title"
                                value={title}
                                onChange={handleChange}
                                className="mt-2 block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 focus:ring-2 focus:ring-indigo-600 sm:text-sm sm:leading-6"
                                placeholder="Your journal title"
                            />
                        </div>
                        <div>
                            <label htmlFor="article" className="block text-sm font-medium leading-6 text-gray-900">Your Journal</label>
                            <textarea
                                id="article"
                                name="article"
                                rows={10}
                                value={article}
                                onChange={handleChange}
                                className="mt-2 block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 focus:ring-2 focus:ring-indigo-600 sm:text-sm sm:leading-6"
                                placeholder="Write your journal here..."
                            />
                        </div>
                        <div>
                            <label htmlFor="tags" className="block text-sm font-medium leading-6 text-gray-900">Tags</label>
                            <input
                                type="text"
                                name="tags"
                                id="tags"
                                value={tags}
                                onChange={handleChange}
                                className="mt-2 block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 focus:ring-2 focus:ring-indigo-600 sm:text-sm sm:leading-6"
                                placeholder="e.g., travel, food, lifestyle"
                            />
                        </div>
                    </div>

                    {error && <p className="text-red-500 text-center mt-4">{error}</p>}

                    <div className="mt-8 flex justify-end space-x-4">
                        <button type="button" onClick={handleCancel} className="text-lg font-semibold leading-6 text-gray-900">
                            Cancel
                        </button>
                        <button
                            type="submit"
                            className="rounded-md bg-indigo-600 px-6 py-3 text-lg font-semibold text-white shadow-sm hover:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600">
                            Save
                        </button>
                    </div>
                </form>
            </div>
        </div>
        </>
    );
};

export default UpdateJournal;

