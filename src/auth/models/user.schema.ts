import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';
import { UserRole } from '../enums/user-role.enum';
import * as bcrypt from 'bcrypt';

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
        required: [true, 'La fecha de nacimiento es obligatoria'],
        validate: {
        validator: (value: Date) => value <= new Date(),
        message: 'La fecha de nacimiento no puede ser mayor a hoy',
        },
    })
    birthdate: Date;

    @Prop({
        required: [true, 'La contraseña es obligatoria'],
        select: false,
    })
    password: string;

    @Prop({
        enum: UserRole,
        default: UserRole.USER,
    })
    role: UserRole;

    async hashPassword() {
        if (this.password) {
            const salt = await bcrypt.genSalt(10);
            this.password = await bcrypt.hash(this.password, salt);
        }
    }
}

export const UserSchema = SchemaFactory.createForClass(User);

UserSchema.pre('save', async function (next) {
    if (this.isModified('password')) {
        await this.hashPassword();
    }
    next();
});
