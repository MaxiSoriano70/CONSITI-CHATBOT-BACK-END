import { IsEmail, IsString } from "class-validator";

export class ConfirmPasswordResetDto {
    @IsEmail()
    email: string;

    @IsString()
    code: string;

    @IsString()
    newPassword: string;
}
