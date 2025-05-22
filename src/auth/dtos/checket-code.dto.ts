import { IsEmail, IsString } from "class-validator";

export class ChecketCodeDto {
    @IsEmail()
    email: string;

    @IsString()
    code: string;
}
