import mongoose from 'mongoose';

const moodSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    date: { type: Date, required: true },
    mood: { type: String, required: true },
  }, { timestamps: true });
  
  const Mood = mongoose.model('Mood', moodSchema);

  export default Mood;