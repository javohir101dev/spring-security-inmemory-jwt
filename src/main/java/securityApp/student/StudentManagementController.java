package securityApp.student;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementController {

    private final static List<Student> STUDENTS = new ArrayList<>(Arrays.asList(
            new Student(1, "James Bond"),
            new Student(2, "Maria Jones"),
            new Student(3, "Anna Smith")
    ));

    @PreAuthorize(value = "hasAnyRole('ROLE_ADMIN', 'ROLE_ADMINTRAINEE')")
    @GetMapping
    public List<Student> getAllStudents(){
        System.out.println("getAllStudents");
        return STUDENTS;
    }

    @PreAuthorize("hasAnyAuthority('student:write')")
    @PostMapping
    public void registerStudent(@RequestBody Student student){
        System.out.println("registerStudent");
        System.out.println(student);
    }

    @PreAuthorize("hasAnyAuthority('student:write')")
    @DeleteMapping(path = "/{studentId}")
    public void deleteStudent(@PathVariable Integer studentId){
        System.out.println("deleteStudent");
        System.out.println(studentId);
    }

    @PreAuthorize("hasAnyAuthority('student:write')")
    @PutMapping(path = "/{studentId}")
    public void updateStudent(@RequestBody Student student, @PathVariable String studentId){
        System.out.println("updateStudent");
        System.out.printf("%s %s%n", studentId, student);
    }

}
