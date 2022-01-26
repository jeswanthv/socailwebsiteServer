import { User } from '../entities/User';
import { MyContext } from 'src/types';
import {
  Arg,
  Ctx,
  Field,
  InputType,
  Mutation,
  ObjectType,
  Query,
  Resolver,
} from 'type-graphql';
import argon2 from 'argon2';

@InputType()
class UsernamePasswordInput {
  @Field()
  username: string;
  @Field()
  password: string;
}

@ObjectType()
class FieldError {
  @Field()
  field: string;

  @Field()
  message: string;
}

@ObjectType()
class UserResponse {
  @Field(() => [FieldError], { nullable: true })
  error?: FieldError[];

  @Field(() => User, { nullable: true })
  user?: User;
}

@Resolver()
export class UserResolver {
  @Query(() => User, { nullable: true })
  async me(@Ctx() { em, req }: MyContext) {
    if (!req.session.userId) {
      return null;
    }
    const user = await em.findOne(User, { id: req.session.userId });
    return user;
  }

  //create a user
  @Mutation(() => UserResponse)
  async register(
    @Arg('options') options: UsernamePasswordInput,
    @Ctx() { em, req }: MyContext
  ): Promise<UserResponse> {
    //username length
    if (options.username.length <= 2) {
      return {
        error: [
          {
            field: 'username',
            message: 'length must be greater than 2',
          },
        ],
      };
    }
    //passwod length
    if (options.password.length <= 2) {
      return {
        error: [
          {
            field: 'password',
            message: 'length must be greater than 2',
          },
        ],
      };
    }
    //hash the password
    const hashedPassword = await argon2.hash(options.password);
    const user = em.create(User, {
      username: options.username,
      password: hashedPassword,
    });
    try {
      await em.persistAndFlush(user);
    } catch (err) {
      //duplicate username
      if (err.code === '23505' || err.detail.includes('already exsits')) {
        return {
          error: [
            {
              field: 'username',
              message: 'username already taken',
            },
          ],
        };
      }
    }

    //automatic session has been intiated(loggedin)
    //after signup
    req.session.userId = user.id;

    return { user };
  }

  //Login the user
  @Mutation(() => UserResponse)
  async login(
    @Arg('options') options: UsernamePasswordInput,
    @Ctx() { em, req }: MyContext
  ): Promise<UserResponse> {
    const user = await em.findOne(User, { username: options.username });
    if (!user) {
      return {
        error: [
          {
            field: 'username',
            message: "User doesn't exist",
          },
        ],
      };
    }
    const valid = await argon2.verify(user.password, options.password);
    if (!valid) {
      return {
        error: [
          {
            field: 'password',
            message: 'incorrect password',
          },
        ],
      };
    }
    req.session.userId = user.id;
    return { user };
  }
}
