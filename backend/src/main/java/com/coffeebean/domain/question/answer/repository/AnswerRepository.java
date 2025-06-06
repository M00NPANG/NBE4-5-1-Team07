package com.coffeebean.domain.question.answer.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.coffeebean.domain.question.answer.entity.Answer;
import com.coffeebean.domain.question.question.entity.Question;

@Repository
public interface AnswerRepository extends JpaRepository<Answer, Long> {
	Answer findByQuestion(Question question);
}
