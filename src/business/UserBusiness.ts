import { UserDatabase } from "../database/UserDatabase"
import { AuthenticationError } from "../errors/AuthenticationError"
import { AuthorizationError } from "../errors/AuthorizationError"
import { NotFoundError } from "../errors/NotFoundError"
import { ParamsError } from "../errors/ParamsError"
import { IDeleteUsersInputDTO, ILoginInputDTO, ISignupInputDTO, User, USER_ROLES } from "../models/User"
import { Authenticator, ITokenPayload } from "../services/Authenticator"
import { HashManager } from "../services/HashManager"
import { IdGenerator } from "../services/IdGenerator"

export class UserBusiness {
    constructor(
        private userDatabase: UserDatabase,
        private idGenerator: IdGenerator,
        private hashManager: HashManager,
        private authenticator: Authenticator
    ) { }

    public signup = async (input: ISignupInputDTO) => {
        const name = input.name
        const email = input.email
        const password = input.password

        if (!name || !email || !password) {
            throw new ParamsError()
        }

        if (typeof name !== "string" || name.length < 3) {
            throw new Error("name deve possuir ao menos 3 caracteres");
        }

        if (!email.match(/^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/)) {
            throw new Error("Parâmetro 'email' inválido")
        }

        if (typeof password !== "string" || password.length < 6) {
            throw new Error("Parâmetro 'password' inválido");
        }

        const userDB = await this.userDatabase.findByEmail(email)

        if (userDB) {
            throw new Error("E-mail já cadastrado");
        }

        const id = this.idGenerator.generate()
        const hasheadPassword = await this.hashManager.hash(password)

        const user = new User(
            id,
            name,
            email,
            hasheadPassword,
            USER_ROLES.NORMAL
        )

        await this.userDatabase.createUser(user)

        const payload: ITokenPayload = {
            id: user.getId(),
            role: user.getRole()
        }

        const token = this.authenticator.generateToken(payload)

        const response = {
            message: "Usuário cadastrado com sucesso",
            token
        }
        return response
    }

    public login = async (input: ILoginInputDTO) => {
        const email = input.email
        const password = input.password

        if (!email || !password) {
            throw new Error("Um ou mais parâmetros faltando")
        }

        if (typeof email !== "string" || email.length < 3) {
            throw new Error("Parâmetro 'email' inválido")
        }

        if (!email.match(/^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/)) {
            throw new Error("Parâmetro 'email' inválido")
        }

        if (typeof password !== "string" || password.length < 3) {
            throw new Error("Parâmetro 'password' inválido")
        }

        const userDB = await this.userDatabase.findByEmail(email)

        if (!userDB) {
            throw new Error("E-mail não cadastrado")
        }

        const user = new User(
            userDB.id,
            userDB.name,
            userDB.email,
            userDB.password,
            userDB.role
        )

        const isPasswordCorrect = await this.hashManager.compare(password, user.getPassword())

        if (!isPasswordCorrect) {
            throw new AuthenticationError()
        }

        const payload: ITokenPayload = {
            id: user.getId(),
            role: user.getRole()
        }

        const token = this.authenticator.generateToken(payload)

        const response = {
            message: "Login realizado com sucesso",
            token
        }

        return response
    }

    public deleteUser = async (input: IDeleteUsersInputDTO) => {
        const token = input.token
        const id = input.id

        if (!token) {
            throw new AuthorizationError()
        }
        if (!id) {
            throw new Error("Informe a ID a ser deletada");
        }

        const userExist = await this.userDatabase.findById(id);
        if (!userExist) {
            throw new NotFoundError()
        }

        const payload = this.authenticator.getTokenPayload(token);
        if (!payload) {
            throw new Error("Token inválido");
        }

        if (payload.id === id) {
            throw new Error("Você não pode remover a si mesmo");
        }

        if (payload.role !== USER_ROLES.ADMIN) {
            throw new AuthorizationError()
        }

        await this.userDatabase.deleteUser(id);

        const response = {
            message: "Usuário deletado com sucesso!"
        }

        return response
    }

}