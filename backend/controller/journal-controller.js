import Journal from "../models/journalModel.js";
import User from "../models/userModel.js";
import jwt from 'jsonwebtoken';
import mongoose from "mongoose";

export const create_journal = async (req, res) => {
    const { title, article, tags } = req.body;
    const { username } = req.params;
    console.log(username);
    console.log(req.body);

    try {
        const user = await User.findOne({ username });
        console.log(user);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const journalData = {
            title,
            article,
            tags,
        };

        if (req.file) {
            journalData.coverPicture = req.file.path; // save the file path to the journal document
        }

        const journalAdded = await Journal.create(journalData);

        user.journals.push(journalAdded._id);
        await user.save();

        res.status(201).json(journalAdded);
    } catch (error) {
        console.log(error);
        res.status(400).json({ error: error.message });
    }
};

// read all your journals only your journals 
export const getPostsByUsername = async (req, res) => {
    const username = req.params.username;
    try {
        // Find the user document based on the provided username
        const user = await User.findOne({ username }).populate('journals');

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // The journals array is already populated with the actual journal documents
        const journals = user.journals;

        return res.status(200).json(journals);
    } catch (error) {
        console.error('Error fetching journals by username:', error);
        return res.status(500).json({ error: error.message });
    }
};


// update your journal
export const update_journal = async (req, res) => {
    try {
        const { id } = req.params;

        if (!mongoose.Types.ObjectId.isValid(id)) {
            return res.status(404).json({ msg: 'No journal with that id' });
        }

        const journal = await Journal.findById(id);

        if (!journal) {
            return res.status(404).json({ msg: 'Journal not found' });
        }

        // Update journal fields (only the ones provided in the request body)
        Object.assign(journal, req.body);

        await journal.save();
        return res.status(200).json(journal);
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
};


// delete journal 
export const delete_journal = async (req, res) => {
    try {
        const { id, username } = req.params;

        if (!mongoose.Types.ObjectId.isValid(id)) {
            return res.status(404).json({ msg: 'No journal with that ID' });
        }

        // Find the user by username
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(404).json({ msg: 'User not found!' });
        }

        // Find and delete the journal
        const journal = await Journal.findByIdAndDelete(id);
        if (!journal) {
            return res.status(404).json({ msg: 'Journal not found!' });
        }

        // Remove the journal ID from the user's journals array
        user.journals = user.journals.filter(journalId => journalId.toString() !== id);
        await user.save();

        return res.status(200).json({ msg: 'Journal deleted successfully!' });
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
};


// Fetch a single journal post by its ID
export const getJournalById = async (req, res) => {
    try {
        const { id } = req.params;

        // if (!mongoose.Types.ObjectId.isValid(id)) {
        //     return res.status(404).json({ error: 'Invalid journal ID' });
        // }

        // Find the journal by its ID
        const journal = await Journal.findById(id);

        if (!journal) {
            return res.status(404).json({ error: 'Journal not found' });
        }

        return res.status(200).json(journal);
    } catch (error) {
        console.error('Error fetching journal by ID:', error);
        return res.status(500).json({ error: 'Internal server error' });
    }
};

