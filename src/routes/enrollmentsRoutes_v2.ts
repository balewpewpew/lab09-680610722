import { Router, type Request, type Response } from "express";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

import type { Student,User, UserPayload, CustomRequest, Enrollment } from "../libs/types.ts";
import {
    zCourseId,
    zStudentId
} from "../libs/zodValidators.ts"
// import database
import { students, courses, users, enrollments, reset_users } from "../db/db.ts";
import { success } from "zod";
import { authenticateToken } from "../middlewares/authenMiddleware.js";
import { checkRoleAdmin } from "../middlewares/checkRoleAdminMiddleware.ts";
import { checkRoleStudent } from "../middlewares/checkRoleStudentMiddleware.ts";
import { token } from "morgan";

const router = Router();

// GET /api/v2/enrollments
router.get("/", authenticateToken,(req: CustomRequest, res: Response) => {
  try {
    const user = req.user;
    
    if(!user){
        return res.status(403).json({
            success: false,
            message: "Unauthorized user"
        })
    }
    if(user.role === "STUDENT"){
        if(!user.studentId){
            return res.status(401).json({
                ok: false,
                message: "studentId invalid"
            })
        }
        const founduser = users.find((u) => u.username === user.username);
        if(!founduser){
            return res.status(404).json({
                ok: false,
                message: "not found user"
            })
        }
        const targetstudentId = founduser.studentId;
        const matchedEnrollments = enrollments.filter(
            (e) => e.studentId === targetstudentId
        );
        const courseIdList = matchedEnrollments.map((e) => e.courseId);
        const foundCourses = courses
            .filter((c) => courseIdList.includes(c.courseId))
            .map((c) => ({
                courseId: String(c.courseId),
                title: c.courseTitle,
            }));
        return res.status(200).json({
            ok: true,
            courses: foundCourses,
        });
    }
    if(user.role === "ADMIN"){
        return res.status(200).json({
            ok: true,
            data: enrollments,
        });
    }
  } catch (err) {
    return res.status(200).json({
      success: false,
      message: "Something is wrong, please try again",
      error: err,
    });
  }
});

// POST /api/v2/enrollments/login
router.post("/login", (req: CustomRequest, res: Response) => {
  const { username , password } = req.body;
  // 2. check if user exists (search with username & password in DB)
  const user = users.find((u) => u.username === username && u.password === password);
  //if user not found
  if(!user){
    return res.status(401).json({
        success: false,
        message: "Invalide username or password"
    });
  }
  // 3. create JWT token (with user info object as payload) using JWT_SECRET_KEY
  const jwt_secret = process.env.JWT_SECRET || "this_is_my_super_secret";
  const token = jwt.sign(
    {
        //App payload
        username: user.username,
        studentId: user.password,
        role: user.role
    },
    jwt_secret,
    {expiresIn:"30m"}
  )
  //    (optional: save the token as part of User data)
  user.tokens = user.tokens ? [...user.tokens, token] : [token];
  // 4. send HTTP response with JWT token
  return res.status(200).json({
    success: true,
    message: "Login successful",
    token: token
  })

  return res.status(500).json({
    success: false,
    message: "POST /api/v2/users/login has not been implemented yet",
  });
});

router.post("/", authenticateToken , checkRoleStudent , (req: CustomRequest, res: Response)=>{
    try{
        const user = req.user;
        const courseid = req.body.courseId;
        const us = users.find((u)=>user?.username === u.username)
        const newenroll :Enrollment = {
            studentId: String(us?.studentId),
            courseId: String(courseid)
        }
        console.log(user?.studentId);
        const samecourse = enrollments.some(
            (e)=>e.studentId === newenroll.studentId && e.courseId === newenroll.courseId
        )
        enrollments.push(newenroll);
        console.log(newenroll);
        return res.status(200).json({
            ok: true,
            message: `enroll ${newenroll.courseId} successfully`
        })
    }catch (err) {
        return res.status(200).json({
            success: false,
            message: "Something is wrong, please try again",
            error: err,
        });
    }
})


//POST /api/v2/users/logout
router.post("/logout", authenticateToken, (req: CustomRequest, res: Response) => {
  // 1. check Request if "authorization" header exists
  //    and container "Bearer ...JWT-Token..."

  // 2. extract the "...JWT-Token..." if available

  // 3. verify token using JWT_SECRET_KEY and get payload (username, studentId and role)

  // 4. check if user exists (search with username)
  const payload_user = req.user;
  const payload_token = req.token;
  const user = users.find((u)=> u.username === payload_user?.username)
  if(!user){
    return res.status(401).json({
        success: false,
        message: "User not found"
    })
  }
  // 5. proceed with logout process and return HTTP response
  //    (optional: remove the token from User data)
  user.tokens = user.tokens?.filter((t) => t !== payload_token)
  return res.status(200).json({
    success: true,
    message: "Sign out Successful"
  })
//   return res.status(500).json({
//     success: false,
//     message: "POST /api/v2/users/logout has not been implemented yet",
//   });
});

// POST /api/v2/users/reset
// router.post("/reset", (req: Request, res: Response) => {
//   try {
//     reset_users();
//     return res.status(200).json({
//       success: true,
//       message: "User database has been reset",
//     });
//   } catch (err) {
//     return res.status(500).json({
//       success: false,
//       message: "Something is wrong, please try again",
//       error: err,
//     });
//   }
// });

router.delete("/",authenticateToken,checkRoleStudent,(req: CustomRequest, res: Response)=> {
    try{
        const user = req.user;
        if(!user){
            return res.status(403).json({
                success: false,
                message: "Unauthorized user"
            })
        }
        const founduser = users.find((u) => u.username === user.username);
        if(!founduser){
            return res.status(404).json({
                success: false,
                message: "not found user"
            })
        }
        const targetstudentId = founduser.studentId;
        const courseId = req.body.courseId;
        const result = zCourseId.safeParse(courseId);
        if(!result.success){
            return res.status(400).json({
                ok: false,
                message: "Validation failed",
                errors: result.error.issues[0]?.message,
            });
        }
        const index = enrollments.findIndex((e)=> e.studentId === String(targetstudentId) && e.courseId === String(courseId));
        if (index === -1) {
            return res.status(404).json({
                ok: false,
                message: "Enrollment does not exist",
            });
        }
            
        enrollments.splice(index, 1);
         return res.status(200).json({
            ok: true,
            message: "You has dropped from this course. See you next semester.",
         });

    } catch (err) {
        return res.status(500).json({
            ok: false,
            message: "Something is wrong, please try again",
            error: err,
        });
   }
})

export default router;