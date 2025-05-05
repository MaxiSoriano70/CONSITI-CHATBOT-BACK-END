import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';
import { UserRole } from '../enums/user-role.enum';
import * as bcrypt from 'bcrypt';
import { hashPassword } from '../utils/hash-password.util';

@Schema()
export class User extends Document {
    @Prop({
        required: [true, 'El email es obligatorio'],
        unique: true,
        match: [/\S+@\S+\.\S+/, 'Debe tener formato de email válido'],
    })
    email: string;

    @Prop({
        required: [true, 'El nombre completo es obligatorio'],
        minlength: [3, 'El nombre debe tener al menos 3 letras'],
        match: [/^[A-Za-zÁÉÍÓÚÑáéíóúñ]+(?: [A-Za-zÁÉÍÓÚÑáéíóúñ]+)*$/, 'El nombre solo puede contener letras y espacios'],
    })
    fullname: string;

    @Prop({
        required: false,
        validate: {
            validator: (value: Date) => !value || value <= new Date(),
            message: 'La fecha de nacimiento no puede ser mayor a hoy',
        },
    })
    birthdate?: Date;

    @Prop({
        required: false,
        select: false,
    })
    password?: string;

    @Prop({
        enum: UserRole,
        default: UserRole.USER,
    })
    role: UserRole;
}


export const UserSchema = SchemaFactory.createForClass(User);

UserSchema.pre('save', async function(next) {
    if (this.isModified('password') && this.password) {
        try {
            const salt = await bcrypt.genSalt(10);
            this.password = await bcrypt.hash(this.password, salt);
            next();
        } catch (error) {
            next(error);
        }
    } else {
        next();
    }
});