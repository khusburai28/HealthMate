import React from 'react';

const Answer = ({ index, value, checked, handleChange }) => {
  return (
    <label className="flex items-center">
      <input
        type="radio"
        name={`question-${index}`}
        value={value}
        checked={checked}
        onChange={() => handleChange(index, value)}
        className="mr-2"
      />
      {value}
    </label>
  );
};

export default Answer;
