import { UserRole } from '../enums/user-role.enum';

export class UserResponseDto {
    _id: string;
    email: string;
    fullname: string;
    birthdate: Date;
    role: UserRole;
}

export function toUserResponse(user: any): UserResponseDto {
    return {
        _id: user._id.toString(),
        email: user.email,
        fullname: user.fullname,
        birthdate: user.birthdate,
        role: user.role,
    };
}
