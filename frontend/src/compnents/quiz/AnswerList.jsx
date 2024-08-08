import React from 'react';
import Answer from './Answer';

const AnswerList = ({ answers, index, options, handleChange }) => {
  return (
    <div className="flex flex-col space-y-2">
      {options.map((option, optionIndex) => (
        <Answer
          key={optionIndex}
          index={index}
          value={option}
          checked={answers[index] === option}
          handleChange={handleChange}
        />
      ))}
    </div>
  );
};

export default AnswerList;
