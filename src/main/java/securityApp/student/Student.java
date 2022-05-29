package securityApp.student;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

@RequiredArgsConstructor
@Getter
@ToString
public class Student {

    private final Integer studentId;
    private final String studentName;

}
