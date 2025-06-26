import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";

@Schema()
export class Message extends Document {
    @Prop({ required: true })
    userId: string;

    @Prop({ required: true })
    question: string;

    @Prop({ required: true })
    answers: string[];

    @Prop({ default: Date.now })
    createdAt: Date;
}

export const MessageSchema = SchemaFactory.createForClass(Message);
