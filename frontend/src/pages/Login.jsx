import axios from "axios";
import { useNavigate } from "react-router-dom";

export const Login = () => {
	const navigate = useNavigate();

	const handlerSubmit = async (event) => {
		event.preventDefault();

		const formData = new FormData(event.target);

		const requestData = {
			email: formData.get("email"),
			password: formData.get("password"),
		};

		try {
			await axios.post("http://localhost:8000/api/auth/login", requestData, {
				withCredentials: true,
			});
			navigate("/");
		} catch (error) {
			console.error("Error:", error);
		}
	};

	return (
		<div className="flex min-h-full flex-col justify-center px-6 py-12 lg:px-8">
			<div className="sm:mx-auto sm:w-full sm:max-w-sm">
				<h2 className="mt-10 text-center text-2xl font-bold leading-9 tracking-tight text-gray-900">
					Inicia sesion en tu cuenta
				</h2>
			</div>

			<div className="mt-10 sm:mx-auto sm:w-full sm:max-w-sm">
				<form className="space-y-6" onSubmit={handlerSubmit}>
					<div>
						<label
							htmlFor="email"
							className="block text-sm font-medium leading-6 text-gray-900"
						>
							Email
						</label>
						<div className="mt-2">
							<input
								id="email"
								name="email"
								type="email"
								autoComplete="email"
								required
								className="block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
							/>
						</div>
					</div>

					<div>
						<div className="flex items-center justify-between">
							<label
								htmlFor="password"
								className="block text-sm font-medium leading-6 text-gray-900"
							>
								Contraseña
							</label>
						</div>
						<div className="mt-2">
							<input
								id="password"
								name="password"
								type="password"
								autoComplete="current-password"
								required
								className="block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
							/>
						</div>
					</div>

					<div>
						<button
							type="submit"
							className="flex w-full justify-center rounded-md bg-indigo-600 px-3 py-1.5 text-sm font-semibold leading-6 text-white shadow-sm hover:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600"
						>
							Iniciar Sesion
						</button>
					</div>
					<p className="mt-10 text-center text-sm text-gray-500">
						¿No tienes cuenta?
						<a
							href="/register"
							className=" ml-2 font-semibold leading-6 text-indigo-600 hover:text-indigo-500"
						>
							Registrate
						</a>
					</p>
				</form>
			</div>
		</div>
	);
};
