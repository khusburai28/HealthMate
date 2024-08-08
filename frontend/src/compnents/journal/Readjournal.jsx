import React, { useState, useEffect } from 'react';
import { Link, useParams, useNavigate } from 'react-router-dom'; // Import useNavigate
import axios from 'axios';
import defaultCoverImage from './download.jpg'; 
import './Modal.css';

const Readjournal = () => {
    const [journals, setJournals] = useState([]);
    const [showConfirmationModal, setShowConfirmationModal] = useState(false); // State for confirmation modal
    const [journalToDelete, setJournalToDelete] = useState(null); // State to store journal to delete
    const { username } = useParams();
    const navigate = useNavigate();

    useEffect(() => {
        const fetchJournals = async () => {
            try {
                const response = await axios.get(`http://localhost:8000/${username}/journals`);
                setJournals(response.data);
            } catch (error) {
                console.error('Error fetching journals:', error);
            }
        };
        fetchJournals();
    }, [username]);

    const shortenText = (text, maxLength) => {
        if (text.length <= maxLength) return text;
        return text.substr(0, maxLength) + '...';
    };

    const handleEdit = (journalId) => {
        navigate(`/${username}/journals/${journalId}/edit`);
    };

    const handleDelete = (journalId) => {
        setJournalToDelete(journalId); // Set the journal to delete
        setShowConfirmationModal(true); // Show confirmation modal
    };

    const confirmDelete = async () => {
        try {
            await axios.delete(`http://localhost:8000/journal-delete/${username}/${journalToDelete}`);
            // Remove the deleted journal from the state
            setJournals(journals.filter(journal => journal._id !== journalToDelete));
            // Close the confirmation modal
            setShowConfirmationModal(false);
        } catch (error) {
            console.error('Error deleting journal:', error);
        }
    };

    const closeModal = () => {
        setShowConfirmationModal(false);
    };

    return (
        <div className="bg-white py-24 sm:py-32">
            <div className="mx-auto max-w-7xl px-6 lg:px-8">
                <div className="mx-auto max-w-2xl lg:mx-0">
                    <h2 className="text-3xl font-bold tracking-tight text-gray-900 sm:text-4xl">Your Journal</h2>
                    <p className="mt-2 text-lg leading-8 text-gray-600">
                        Keep your memorable days stored with you!
                    </p>
                </div>
                <div className="mx-auto mt-10 grid max-w-2xl grid-cols-1 gap-x-8 gap-y-16 border-t border-gray-200 pt-10 sm:mt-16 sm:pt-16 lg:mx-0 lg:max-w-none lg:grid-cols-3">
                    {journals.map((journal) => {
                        const coverImage = journal.coverPicture ? `http://localhost:8000/${journal.coverPicture}` : defaultCoverImage;

                        return (
                            <div key={journal._id} className="bg-white shadow-md rounded-lg overflow-hidden relative">
                                <article className="p-6 flex flex-col justify-between h-full">
                                    <div>
                                        <div className="flex items-center gap-x-4 text-xs mb-3">
                                            <time dateTime={journal.createdAt} className="text-gray-500">
                                                {new Date(journal.createdAt).toLocaleDateString()}
                                            </time>
                                        </div>
                                        <div className="group relative">
                                            <h3 className="text-lg font-semibold leading-6 text-gray-900 group-hover:text-gray-600 mb-2">
                                                <Link to={`/${username}/readjournals/${journal._id}`}>
                                                    {journal.title}
                                                </Link>
                                            </h3>
                                            <p className="line-clamp-3 text-sm leading-6 text-gray-600 mb-4">
                                                {shortenText(journal.article, 50)} {/* Show first 50 characters */}
                                            </p>
                                        </div>
                                    </div>
                                    <img src={coverImage} alt="Cover" className="mt-auto h-24 w-full object-cover" />
                                    <div className="flex flex-wrap gap-2 mt-2">
                                        {journal.tags && journal.tags.map((tag, index) => (
                                            <span key={index} className="inline-flex items-center rounded-full bg-blue-100 px-3 py-0.5 text-sm font-medium text-blue-800">
                                                {tag}
                                            </span>
                                        ))}
                                    </div>
                                    <div className="absolute top-2 right-2 flex gap-2">
                                        <button
                                            className="bg-blue-500 text-white px-3 py-1 rounded-md hover:bg-blue-600"
                                            onClick={() => handleEdit(journal._id)}
                                        >
                                            Edit
                                        </button>
                                        <button
                                            className="bg-red-500 text-white px-3 py-1 rounded-md hover:bg-red-600"
                                            onClick={() => handleDelete(journal._id)}
                                        >
                                            Delete
                                        </button>
                                    </div>
                                </article>
                            </div>
                        );
                    })}
                </div>
            </div>
            {showConfirmationModal && (
  <div className="modal-overlay">
    <div className="modal-content">
      <p className="text-lg font-semibold mb-4">Are you sure you want to delete this journal?</p>
      <div className="modal-buttons">
        <button className="bg-red-500 text-white px-4 py-2 rounded-md mr-2 hover:bg-red-600" onClick={confirmDelete}>Delete</button>
        <button className="bg-gray-300 text-gray-800 px-4 py-2 rounded-md hover:bg-gray-400" onClick={closeModal}>Cancel</button>
      </div>
    </div>
  </div>
)}
        </div>
    );
}

export default Readjournal;


